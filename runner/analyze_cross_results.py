import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


BUG_VERDICTS = {
    "bug_candidate",
    "sanitizer_crash",
    "ubsan_crash",
}

SAFE_VERDICTS = {
    "safe_behavior",
    "fixed_behavior",
    "safe_reject_behavior",
}

HARNESS_ERROR_VERDICTS = {
    "harness_input_error",
    "build_or_template_error",
    "compile_error",
    "timeout",
}

TRIAGE_VERDICTS = {
    "normal_behavior_needs_triage",
    "nonzero_needs_triage",
    "unknown",
}

SEMANTIC_PROJECTION_LIMITATION_VERDICTS = {
    "semantic_projection_limitation",
}

NORMAL_EXPECTED_VERDICTS = {
    "normal_expected_behavior",
}


NOT_ANALYZED_VERDICTS = {
    "not_executed",
    "reference_artifact_skipped",
    "unknown_library_skipped",
}


def case_template(case: Dict[str, Any] | None) -> Dict[str, Any]:
    if not case:
        return {}
    value = case.get("template", {})
    return value if isinstance(value, dict) else {}


def case_template_id(case: Dict[str, Any] | None) -> str:
    tmpl = case_template(case)
    return str(case.get("source_template_id") or tmpl.get("source_template_id") or case.get("template_id") or tmpl.get("template_id") or "") if case else ""


def case_harness_family(case: Dict[str, Any] | None) -> str:
    tmpl = case_template(case)
    return str(case.get("harness_family") or tmpl.get("harness_family") or "") if case else ""


def case_oracle_type(case: Dict[str, Any] | None) -> str:
    tmpl = case_template(case)
    return str(case.get("oracle_type") or tmpl.get("oracle_type") or "") if case else ""


def case_target_api(case: Dict[str, Any] | None) -> str:
    tmpl = case_template(case)
    return str(case.get("target_api") or tmpl.get("target_api") or "") if case else ""


def case_target_library(case: Dict[str, Any] | None) -> str:
    tmpl = case_template(case)
    return str(case.get("target_library") or tmpl.get("target_library") or case.get("library") or "") if case else ""


def ast_summary(case: Dict[str, Any] | None) -> Dict[str, Any]:
    if not case:
        return {}
    value = case.get("ast_mask_selection", {})
    return value if isinstance(value, dict) else {}


def first_present(*values: str) -> str:
    for value in values:
        if value:
            return value
    return ""


def load_summary(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_case_id(relative_source: str) -> str:
    name = Path(relative_source).name
    m = re.search(r"(case_\d+)", name)
    if m:
        return m.group(1)

    # fallback for unrendered/default source-target template pairs
    if name.startswith("default_") or name.startswith("tmpl_"):
        return "default"

    return Path(relative_source).stem


def extract_template_path(relative_source: str) -> str:
    p = Path(relative_source)
    if len(p.parts) <= 1:
        return "."

    # bignum/mpi_write_string/case_0000_mbedtls.c
    # -> bignum/mpi_write_string
    return str(Path(*p.parts[:-1]))


def group_cases(cases: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    groups = defaultdict(lambda: {"cases": {}})

    for c in cases:
        rel = c.get("relative_source", "")
        case_id = extract_case_id(rel)
        template_path = extract_template_path(rel)
        template_id = case_template_id(c)
        target_api = case_target_api(c)
        key_parts = [template_id or template_path, target_api or "target", case_id]
        key = "/".join(key_parts)

        lib = c.get("library", "unknown")
        if lib == "unknown":
            continue

        groups[key]["template_path"] = template_path
        groups[key]["template_id"] = template_id
        groups[key]["case_id"] = case_id
        groups[key]["target_api"] = target_api
        groups[key]["target_library"] = case_target_library(c)
        groups[key]["harness_family"] = case_harness_family(c)
        groups[key]["oracle_type"] = case_oracle_type(c)
        groups[key]["ast_mask_selection"] = ast_summary(c)
        groups[key]["metadata_files"] = c.get("metadata_files", {}) if isinstance(c.get("metadata_files", {}), dict) else {}
        groups[key]["mutation_mapping"] = c.get("mutation_mapping", {})
        groups[key]["cases"][lib] = c

    return groups


def classify_pair(source: Dict[str, Any] | None, target: Dict[str, Any] | None) -> Dict[str, Any]:
    if source is None or target is None:
        return {
            "migration_verdict": "incomplete_pair",
            "reason": "Source or target library result is missing.",
        }

    source_v = source.get("verdict", "unknown")
    target_v = target.get("verdict", "unknown")

    if source_v in NOT_ANALYZED_VERDICTS or target_v in NOT_ANALYZED_VERDICTS:
        return {
            "migration_verdict": "migration_not_executed",
            "reason": "At least one side was not executed or was skipped by single-case analysis.",
        }

    if target_v in BUG_VERDICTS:
        if source_v in SAFE_VERDICTS:
            reason = "Source behaved safely while target shows bug-like behavior under the migrated vulnerability pattern."
        else:
            reason = "Target library shows bug-like behavior under migrated vulnerability pattern."
        return {
            "migration_verdict": "migrated_bug_candidate",
            "reason": reason,
        }

    if source_v in BUG_VERDICTS and target_v in SAFE_VERDICTS:
        return {
            "migration_verdict": "source_bug_target_safe",
            "reason": "Source shows bug-like behavior but target appears safe for the migrated case.",
        }

    if target_v in HARNESS_ERROR_VERDICTS:
        return {
            "migration_verdict": "migration_not_applicable",
            "reason": "Target harness failed to build, run, or construct valid input.",
        }

    if source_v in HARNESS_ERROR_VERDICTS:
        return {
            "migration_verdict": "source_harness_error",
            "reason": "Source harness failed, so migration comparison is unreliable.",
        }

    if source_v in SAFE_VERDICTS and target_v in SAFE_VERDICTS:
        return {
            "migration_verdict": "migrated_safe",
            "reason": "The vulnerability pattern was migrated and both source/target behaved safely.",
        }

    if target_v in SEMANTIC_PROJECTION_LIMITATION_VERDICTS:
        return {
            "migration_verdict": "migration_semantic_projection_limitation",
            "reason": (
                "Target behavior reflects an API semantic projection limitation, "
                "not a valid migrated vulnerability candidate."
            ),
        }

    if target_v in NORMAL_EXPECTED_VERDICTS and source_v not in BUG_VERDICTS:
        return {
            "migration_verdict": "migration_expected_behavior",
            "reason": (
                "Target library showed expected normal behavior for this migrated "
                "case and no source/target bug evidence was observed."
            ),
        }

    if target_v in TRIAGE_VERDICTS or source_v in TRIAGE_VERDICTS:
        return {
            "migration_verdict": "migration_needs_triage",
            "reason": "At least one side produced a result requiring manual or LLM triage.",
        }

    return {
        "migration_verdict": "migration_unknown",
        "reason": f"Unhandled source/target verdicts: {source_v} / {target_v}",
    }


def analyze_cross(summary: Dict[str, Any], source_lib: str, target_lib: str) -> Dict[str, Any]:
    cases = summary.get("cases", [])
    groups = group_cases(cases)

    pair_results = []

    for key, group in sorted(groups.items()):
        source = group["cases"].get(source_lib)
        target = group["cases"].get(target_lib)

        pair_class = classify_pair(source, target)

        harness_family = first_present(case_harness_family(source), case_harness_family(target), group.get("harness_family", ""))
        oracle_type = first_present(case_oracle_type(source), case_oracle_type(target), group.get("oracle_type", ""))
        target_api = first_present(case_target_api(target), group.get("target_api", ""))
        target_library = first_present(case_target_library(target), group.get("target_library", ""), target_lib)
        template_id = first_present(case_template_id(source), case_template_id(target), group.get("template_id", ""))

        result = {
            "pair_key": key,
            "template_path": group.get("template_path"),
            "template_id": template_id,
            "case_id": group.get("case_id"),
            "harness_family": harness_family,
            "oracle_type": oracle_type,
            "source_library": source_lib,
            "target_library": target_library,
            "target_api": target_api,
            "source_verdict": source.get("verdict") if source else None,
            "target_verdict": target.get("verdict") if target else None,
            "source_relative_source": source.get("relative_source") if source else None,
            "target_relative_source": target.get("relative_source") if target else None,
            "source_case": source or {},
            "target_case": target or {},
            "metadata_files": group.get("metadata_files", {}),
            "ast_mask_selection": ast_summary(target) or ast_summary(source) or group.get("ast_mask_selection", {}),
            "mutation_mapping": group.get("mutation_mapping", {}),
            **pair_class,
        }

        pair_results.append(result)

    counts = Counter(p["migration_verdict"] for p in pair_results)
    family_counts = Counter(p.get("harness_family", "") for p in pair_results if p.get("harness_family"))
    oracle_counts = Counter(p.get("oracle_type", "") for p in pair_results if p.get("oracle_type"))
    target_api_counts = Counter(p.get("target_api", "") for p in pair_results if p.get("target_api"))

    return {
        "source_library": source_lib,
        "target_library": target_lib,
        "total_pairs": len(pair_results),
        "migration_verdict_counts": dict(counts),
        "harness_family_counts": dict(family_counts),
        "oracle_type_counts": dict(oracle_counts),
        "target_api_counts": dict(target_api_counts),
        "pairs": pair_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze cross-library migration results.")
    parser.add_argument(
        "--input",
        default="runner/results/run_cross_mpi_write_string.summary.json",
        help="Input summary json from runner.analyze_results.",
    )
    parser.add_argument(
        "--output",
        default="runner/results/run_cross_mpi_write_string.migration_summary.json",
        help="Output migration summary json.",
    )
    parser.add_argument(
        "--pair-output",
        default="runner/results/run_cross_mpi_write_string.migration_pairs.jsonl",
        help="Output per-pair migration jsonl.",
    )
    parser.add_argument("--source-lib", default="mbedtls")
    parser.add_argument("--target-lib", default="openssl")

    args = parser.parse_args()

    summary = load_summary(Path(args.input))
    result = analyze_cross(summary, args.source_lib, args.target_lib)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    pair_path = Path(args.pair_output)
    with pair_path.open("w", encoding="utf-8") as f:
        for p in result["pairs"]:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"[OK] migration summary written to {out_path}")
    print(f"[OK] migration pairs written to {pair_path}")
    print(f"[INFO] total pairs: {result['total_pairs']}")
    print(f"[INFO] migration verdict counts: {result['migration_verdict_counts']}")
    print(f"[INFO] harness family counts: {result.get('harness_family_counts', {})}")
    print(f"[INFO] target API counts: {result.get('target_api_counts', {})}")

    for p in result["pairs"][:10]:
        print(
            p["case_id"],
            p["source_verdict"],
            "->",
            p["target_verdict"],
            p["migration_verdict"],
            p.get("harness_family", ""),
            p.get("target_api", ""),
            p["mutation_mapping"],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
