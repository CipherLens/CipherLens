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


def load_summary(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_case_id(relative_source: str) -> str:
    name = Path(relative_source).name
    m = re.search(r"(case_\d+)", name)
    if m:
        return m.group(1)

    # fallback for default_mbedtls.c
    if name.startswith("default_"):
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
        key = f"{template_path}/{case_id}"

        lib = c.get("library", "unknown")
        groups[key]["template_path"] = template_path
        groups[key]["case_id"] = case_id
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

    if target_v in BUG_VERDICTS:
        return {
            "migration_verdict": "migrated_bug_candidate",
            "reason": "Target library shows bug-like behavior under migrated vulnerability pattern.",
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

        result = {
            "pair_key": key,
            "template_path": group.get("template_path"),
            "case_id": group.get("case_id"),
            "source_library": source_lib,
            "target_library": target_lib,
            "source_verdict": source.get("verdict") if source else None,
            "target_verdict": target.get("verdict") if target else None,
            "source_relative_source": source.get("relative_source") if source else None,
            "target_relative_source": target.get("relative_source") if target else None,
            "mutation_mapping": group.get("mutation_mapping", {}),
            **pair_class,
        }

        pair_results.append(result)

    counts = Counter(p["migration_verdict"] for p in pair_results)

    return {
        "source_library": source_lib,
        "target_library": target_lib,
        "total_pairs": len(pair_results),
        "migration_verdict_counts": dict(counts),
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

    for p in result["pairs"][:10]:
        print(
            p["case_id"],
            p["source_verdict"],
            "->",
            p["target_verdict"],
            p["migration_verdict"],
            p["mutation_mapping"],
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
