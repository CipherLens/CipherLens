"""Plan X.509 valid-prefix mutation cases from verified DER/PEM seeds.

This module writes mutation plans and mutated input bytes only. It does not
render C harnesses, compile, run fuzz harnesses, write feedback, mutate
knowledge/pattern-bank state, call an LLM, or claim vulnerabilities.
"""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


TASK = "x509_valid_prefix_mutation_plan_v1"


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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed_by_format(manifest: dict[str, Any], fmt: str) -> dict[str, Any] | None:
    for seed in manifest.get("seeds", []) or []:
        if (
            seed.get("format") == fmt
            and seed.get("parser_valid") is True
            and seed.get("usable_for_valid_prefix_mutation") is True
        ):
            return seed
    return None


def write_input(path: Path, data: bytes) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "path": path.as_posix(),
        "size_bytes": len(data),
        "sha256": sha256_bytes(data),
    }


def der_length_delta(data: bytes) -> bytes:
    if len(data) < 4 or data[0] != 0x30:
        return data[:-1] if len(data) > 1 else b"\x30\x82"
    out = bytearray(data)
    if out[1] == 0x82 and len(out) > 3:
        out[3] = (out[3] + 1) & 0xFF
    elif out[1] == 0x81 and len(out) > 2:
        out[2] = (out[2] + 1) & 0xFF
    else:
        out[1] = (out[1] + 1) & 0x7F
    return bytes(out)


def make_case(
    case_id: str,
    seed: dict[str, Any],
    mutation_strategy: str,
    input_meta: dict[str, Any],
    parser_accept_expected: bool,
    full_consumption_check_required: bool,
    malformed_only_control: bool,
    render_allowed: bool,
    notes: list[str],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "family": "x509_parsing",
        "seed_id": seed.get("seed_id", "synthetic_malformed_control"),
        "seed_format": seed.get("format", "der"),
        "mutation_strategy": mutation_strategy,
        "input_path": input_meta["path"],
        "input_size_bytes": input_meta["size_bytes"],
        "input_sha256": input_meta["sha256"],
        "expected_oracle": {
            "parser_accept_expected": parser_accept_expected,
            "full_consumption_check_required": full_consumption_check_required,
            "malformed_only_control": malformed_only_control,
        },
        "render_allowed": render_allowed,
        "notes": notes,
    }


def build_cases(repo_root: Path, out_dir: Path, der_seed: dict[str, Any] | None, pem_seed: dict[str, Any] | None) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    inputs = out_dir / "inputs" / "mutated"

    if der_seed:
        der_bytes = (repo_root / der_seed["path"]).read_bytes()
        meta = write_input(inputs / "x509_der_valid_plus_trailing_00.der", der_bytes + b"\x00")
        cases.append(
            make_case(
                "x509_parsing__mut_001__der_valid_plus_trailing_00",
                der_seed,
                "der_valid_plus_trailing_garbage",
                meta,
                True,
                True,
                False,
                True,
                ["valid DER seed with one trailing byte; intended full-consumption oracle probe"],
            )
        )

        near = der_length_delta(der_bytes)
        meta = write_input(inputs / "x509_der_near_valid_length_delta.der", near)
        cases.append(
            make_case(
                "x509_parsing__mut_004__der_near_valid_length_delta",
                der_seed,
                "near_valid_der_length_delta",
                meta,
                False,
                True,
                False,
                True,
                ["near-valid DER with small outer length mutation; expected safe reject probe"],
            )
        )

    if pem_seed:
        pem_bytes = (repo_root / pem_seed["path"]).read_bytes()
        meta = write_input(inputs / "x509_pem_valid_plus_trailing_comment.pem", pem_bytes + b"\n# trailing-garbage\n")
        cases.append(
            make_case(
                "x509_parsing__mut_002__pem_valid_plus_trailing_comment",
                pem_seed,
                "pem_valid_plus_trailing_garbage",
                meta,
                True,
                True,
                False,
                True,
                ["valid PEM seed with trailing text; intended full-consumption or PEM parser tolerance probe"],
            )
        )

    malformed_seed = der_seed or pem_seed or {"seed_id": "synthetic_malformed_control", "format": "der"}
    meta = write_input(inputs / "x509_malformed_only_control.der", b"\x30\x82\x00\x08\x02\x01\x01")
    cases.append(
        make_case(
            "x509_parsing__mut_003__malformed_only_control",
            malformed_seed,
            "malformed_only_control",
            meta,
            False,
            False,
            True,
            True,
            ["malformed-only control to calibrate reject-path oracle; not a valid-prefix candidate"],
        )
    )
    return cases


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--seed-manifest", required=True)
    parser.add_argument("--orchestrator-plan", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    seed_manifest_path = (repo_root / args.seed_manifest).resolve()
    orchestrator_plan_path = (repo_root / args.orchestrator_plan).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in ("inputs", "mutation", "plans", "validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    manifest = load_yaml(seed_manifest_path)
    orchestrator_plan = load_yaml(orchestrator_plan_path)
    der_seed = seed_by_format(manifest, "der")
    pem_seed = seed_by_format(manifest, "pem")
    cases = build_cases(repo_root, out_dir, der_seed, pem_seed)

    selection = {
        "schema": "x509_seed_selection_for_mutation_v1",
        "generated_at": now_iso(),
        "seed_manifest": args.seed_manifest,
        "orchestrator_plan": args.orchestrator_plan,
        "seed_manifest_loaded": bool(manifest),
        "der_seed": der_seed,
        "pem_seed": pem_seed,
        "orchestrator_missing_capability": orchestrator_plan.get("missing_capabilities", []),
        "orchestrator_recommended_next_task": orchestrator_plan.get("recommended_next_task", ""),
    }
    dump_yaml(out_dir / "inputs" / "x509_seed_selection.yaml", selection)

    matrix = {
        "schema": "x509_mutation_case_matrix_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "source_seed_manifest": args.seed_manifest,
        "cases": cases,
        "summary": {
            "mutation_case_count": len(cases),
            "strategies": sorted({case["mutation_strategy"] for case in cases}),
            "render_allowed": len([case for case in cases if case["render_allowed"]]),
            "controls": len([case for case in cases if case["expected_oracle"]["malformed_only_control"]]),
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    dump_yaml(out_dir / "mutation" / "x509_mutation_case_matrix.yaml", matrix)

    summary = {
        "schema": "x509_mutation_summary_v1",
        "generated_at": now_iso(),
        "mutation_case_count": len(cases),
        "strategies": matrix["summary"]["strategies"],
        "der_cases": len([case for case in cases if case["seed_format"] == "der"]),
        "pem_cases": len([case for case in cases if case["seed_format"] == "pem"]),
        "malformed_only_controls": matrix["summary"]["controls"],
    }
    dump_yaml(out_dir / "mutation" / "x509_mutation_summary.yaml", summary)

    render_ready = len(cases) > 0 and bool(der_seed or pem_seed)
    readiness = {
        "schema": "x509_render_readiness_plan_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "mutation_case_matrix": (out_dir / "mutation" / "x509_mutation_case_matrix.yaml").as_posix(),
        "render_ready": render_ready,
        "render_allowed_cases": [case["case_id"] for case in cases if case["render_allowed"]],
        "blocked_cases": [],
        "recommended_next_task": "x509_render_plan_v1" if render_ready else "x509_valid_prefix_mutation_fixup_v1",
        "blocked_by": [] if render_ready else ["missing_verified_x509_seed"],
        "policy": {
            "render_executed": False,
            "compile_executed": False,
            "run_executed": False,
            "confirmed_vulnerability_claim": False,
        },
    }
    dump_yaml(out_dir / "plans" / "x509_render_readiness_plan.yaml", readiness)

    qc = {
        "schema": "x509_mutation_plan_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "seed_manifest_loaded": bool(manifest),
        "der_seed_available": der_seed is not None,
        "pem_seed_available": pem_seed is not None,
        "mutation_case_matrix_generated": True,
        "mutation_case_count": len(cases),
        "render_readiness_plan_generated": True,
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
        "quality_status": "pass" if bool(manifest) and len(cases) > 0 else "blocked",
    }
    dump_yaml(out_dir / "validation" / "x509_mutation_plan_quality_checks.yaml", qc)

    report = f"""# {TASK} Report

## Summary

- quality_status: {qc['quality_status']}
- seed_manifest_loaded: {qc['seed_manifest_loaded']}
- DER seed available: {qc['der_seed_available']}
- PEM seed available: {qc['pem_seed_available']}
- mutation cases: {len(cases)}
- strategies: {matrix['summary']['strategies']}
- render_ready: {readiness['render_ready']}

## Policy

No render, compile, run, feedback, knowledge, pattern-bank, adapter recipe,
normalized template, GLM, git, CVE, exploitability, or confirmed vulnerability
claim was produced.
"""
    (out_dir / "reports" / f"{TASK}_report.md").write_text(report, encoding="utf-8")

    print(f"[OK] wrote {TASK} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"cases={len(cases)} der={der_seed is not None} pem={pem_seed is not None} "
        f"render_ready={readiness['render_ready']} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
