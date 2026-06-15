"""Family-agnostic mutation engine.

The engine consumes a family profile plus an operator registry and emits
mutation case matrices. It does not render, compile, run, call an LLM, write
feedback, update knowledge, or claim vulnerabilities.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from mutation.family_profile_loader import family_profile, load_family_profiles, seed_by_format
from mutation.mutation_operator_registry import apply_operator, input_meta, load_operator_registry


TASK = "family_agnostic_mutation_engine_v1"
PREVIOUS_X509_PLAN = Path("artifacts/sprints/x509_valid_prefix_mutation_plan_v1/mutation/x509_mutation_case_matrix.yaml")


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump_yaml(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(obj, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )


def operator_seed_format(operator: dict[str, Any]) -> str:
    return str(operator.get("input_format") or "der")


def case_id_for(family: str, index: int, strategy: str) -> str:
    return f"{family}__generic_mut_{index:03d}__{strategy}"


def output_name(family: str, strategy: str, suffix: str) -> str:
    return f"{family}__{strategy}{suffix}"


def make_case(
    family: str,
    index: int,
    operator_name: str,
    operator: dict[str, Any],
    seed: dict[str, Any],
    meta: dict[str, Any],
) -> dict[str, Any]:
    strategy = str(operator.get("canonical_strategy") or operator_name)
    return {
        "case_id": case_id_for(family, index, strategy),
        "family": family,
        "seed_id": seed.get("seed_id", "synthetic_malformed_control"),
        "seed_format": seed.get("format", operator_seed_format(operator)),
        "operator": operator_name,
        "mutation_strategy": strategy,
        "input_path": meta["path"],
        "input_size_bytes": meta["size_bytes"],
        "input_sha256": meta["sha256"],
        "expected_oracle": {
            "parser_accept_expected": bool(operator.get("parser_accept_expected", False)),
            "full_consumption_check_required": bool(operator.get("full_consumption_check_required", False)),
            "malformed_only_control": bool(operator.get("malformed_only_control", False)),
        },
        "render_allowed": bool(operator.get("render_allowed", True)),
        "notes": operator.get("notes", []),
    }


def generate_cases(
    repo_root: Path,
    out_dir: Path,
    family: str,
    manifest: dict[str, Any],
    profile: dict[str, Any],
    registry: dict[str, Any],
) -> list[dict[str, Any]]:
    cases = []
    operators = registry.get("operators") or {}
    inputs_dir = out_dir / "inputs" / "mutated"
    operator_names = profile.get("operators") or profile.get("mutation_operators") or []
    for index, operator_name in enumerate(operator_names, start=1):
        operator = operators.get(operator_name)
        if not operator:
            continue
        fmt = operator_seed_format(operator)
        seed = seed_by_format(manifest, fmt)
        if not seed and operator.get("static_bytes_hex"):
            seed = {"seed_id": "synthetic_malformed_control", "format": fmt, "path": ""}
            seed_bytes = b""
        elif seed:
            seed_bytes = (repo_root / seed["path"]).read_bytes()
        else:
            continue
        mutated = apply_operator(operator_name, operator, seed_bytes)
        strategy = str(operator.get("canonical_strategy") or operator_name)
        suffix = str(operator.get("output_suffix") or f".{fmt}")
        meta = input_meta(inputs_dir / output_name(family, strategy, suffix), mutated)
        cases.append(make_case(family, index, operator_name, operator, seed, meta))
    return cases


def compare_with_previous(repo_root: Path, generated: dict[str, Any]) -> dict[str, Any]:
    previous = load_yaml(repo_root / PREVIOUS_X509_PLAN)
    previous_cases = previous.get("cases", []) or []
    generated_cases = generated.get("cases", []) or []
    previous_strategies = sorted({case.get("mutation_strategy") for case in previous_cases})
    generated_strategies = sorted({case.get("mutation_strategy") for case in generated_cases})
    return {
        "schema": "x509_specific_vs_generic_comparison_v1",
        "generated_at": now_iso(),
        "previous_plan": PREVIOUS_X509_PLAN.as_posix(),
        "previous_case_count": len(previous_cases),
        "generic_case_count": len(generated_cases),
        "previous_strategies": previous_strategies,
        "generic_strategies": generated_strategies,
        "case_count_matches": len(previous_cases) == len(generated_cases),
        "strategies_match": previous_strategies == generated_strategies,
        "matches_previous_x509_plan": len(previous_cases) == len(generated_cases)
        and previous_strategies == generated_strategies,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family", required=True)
    parser.add_argument("--seed-manifest", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--operator-registry", default="config/mutation_operator_registry.yaml")
    parser.add_argument("--family-profiles", default="config/family_profiles.yaml")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("registry", "profiles", "mutation", "comparison", "plans", "validation", "reports", "inputs"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    registry = load_operator_registry(repo_root / args.operator_registry)
    profiles = load_family_profiles(repo_root / args.family_profiles)
    profile = family_profile(profiles, args.family)
    manifest = load_yaml(repo_root / args.seed_manifest)
    cases = generate_cases(repo_root, out_dir, args.family, manifest, profile, registry)

    matrix = {
        "schema": "generic_mutation_case_matrix_v1",
        "generated_at": now_iso(),
        "family": args.family,
        "source_seed_manifest": args.seed_manifest,
        "profile": args.family,
        "cases": cases,
        "summary": {
            "mutation_case_count": len(cases),
            "strategies": sorted({case["mutation_strategy"] for case in cases}),
            "render_allowed": len([case for case in cases if case["render_allowed"]]),
            "controls": len([case for case in cases if case["expected_oracle"]["malformed_only_control"]]),
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    comparison = compare_with_previous(repo_root, matrix) if args.family == "x509_parsing" else {}
    readiness = {
        "schema": "generic_render_readiness_plan_v1",
        "generated_at": now_iso(),
        "family": args.family,
        "render_ready": len(cases) > 0 and bool(profile.get("render_allowed", True)),
        "render_allowed_cases": [case["case_id"] for case in cases if case["render_allowed"]],
        "recommended_next_task": f"{args.family}_render_plan_v1",
        "blocked_by": [] if cases else ["missing_mutation_cases"],
        "policy": {"render_executed": False, "compile_executed": False, "run_executed": False},
    }
    qc = {
        "schema": "generic_mutation_engine_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "operator_registry_generated": True,
        "family_profile_loaded": bool(profile),
        "generic_engine_used": True,
        "family_specific_mutator_created": False,
        "x509_cases_generated": args.family == "x509_parsing" and len(cases) > 0,
        "x509_case_count": len(cases) if args.family == "x509_parsing" else 0,
        "matches_previous_x509_plan": bool(comparison.get("matches_previous_x509_plan")),
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if bool(profile) and len(cases) > 0 and bool(comparison.get("matches_previous_x509_plan", True))
        else "blocked",
    }

    dump_yaml(out_dir / "registry" / "mutation_operator_registry_snapshot.yaml", registry)
    dump_yaml(out_dir / "profiles" / "family_profiles_snapshot.yaml", profiles)
    dump_yaml(out_dir / "mutation" / "generated_x509_case_matrix.yaml", matrix)
    dump_yaml(out_dir / "comparison" / "x509_specific_vs_generic_comparison.yaml", comparison)
    dump_yaml(out_dir / "plans" / "generic_render_readiness_plan.yaml", readiness)
    dump_yaml(out_dir / "validation" / "generic_mutation_engine_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Summary

- family: {args.family}
- generic cases: {len(cases)}
- strategies: {matrix['summary']['strategies']}
- matches_previous_x509_plan: {comparison.get('matches_previous_x509_plan')}
- quality_status: {qc['quality_status']}

## Policy

No tools script, render, compile, run, feedback, knowledge, pattern-bank,
adapter recipe, normalized template, GLM, git, CVE, exploitability, or confirmed
vulnerability claim was produced.
"""
    (out_dir / "reports" / f"{TASK}_report.md").write_text(report, encoding="utf-8")

    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={args.family} cases={len(cases)} "
        f"matches_previous={comparison.get('matches_previous_x509_plan')} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
