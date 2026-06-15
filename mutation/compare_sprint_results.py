import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def verdict_counts(summary: Dict[str, Any]) -> Dict[str, int]:
    counts = summary.get("verdict_counts", {})
    if not isinstance(counts, dict):
        return {}
    return {str(k): int(v) for k, v in counts.items()}


def status_counts(run_rows: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    return dict(Counter(str(row.get("status") or row.get("raw_status") or "") for row in run_rows))


def repair_count(path: Path) -> int:
    return len(read_jsonl(path))


def case_values(render_matrix: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for case in render_matrix.get("case_matrix", []) or []:
        values = case.get("values", {}) if isinstance(case, dict) else {}
        if isinstance(values, dict):
            out.append({str(k): str(v) for k, v in values.items()})
    return out


def value_counts(values: List[Dict[str, str]]) -> Dict[str, Dict[str, int]]:
    counts: Dict[str, Counter] = {}
    for row in values:
        for dim, value in row.items():
            counts.setdefault(dim, Counter())[value] += 1
    return {dim: dict(counter) for dim, counter in sorted(counts.items())}


def guidance_values(render_matrix: Dict[str, Any], key: str) -> Dict[str, List[str]]:
    guidance = render_matrix.get("feedback_guidance", {})
    if not isinstance(guidance, dict):
        return {}
    values = guidance.get(key, {})
    if not isinstance(values, dict):
        return {}
    return {str(dim): [str(v) for v in vals or []] for dim, vals in values.items()}


def count_guided_values(counts: Dict[str, Dict[str, int]], values: Dict[str, List[str]]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for dim, vals in values.items():
        out[dim] = {value: int(counts.get(dim, {}).get(value, 0)) for value in vals}
    return out


def compare_guided_counts(
    old_counts: Dict[str, Dict[str, int]],
    new_counts: Dict[str, Dict[str, int]],
    values: Dict[str, List[str]],
) -> Dict[str, Dict[str, Dict[str, int]]]:
    out: Dict[str, Dict[str, Dict[str, int]]] = {}
    for dim, vals in values.items():
        dim_out: Dict[str, Dict[str, int]] = {}
        for value in vals:
            old = int(old_counts.get(dim, {}).get(value, 0))
            new = int(new_counts.get(dim, {}).get(value, 0))
            dim_out[value] = {
                "old": old,
                "new": new,
                "delta": new - old,
            }
        out[dim] = dim_out
    return out


def count_delta(new_counts: Dict[str, int], old_counts: Dict[str, int], *keys: str) -> int:
    return sum(new_counts.get(key, 0) for key in keys) - sum(old_counts.get(key, 0) for key in keys)


def build_comparison(args: argparse.Namespace) -> Dict[str, Any]:
    old_summary = load_json(Path(args.old_summary))
    new_summary = load_json(Path(args.new_summary))
    old_behavior = load_json(Path(args.old_behavior_summary))
    new_behavior = load_json(Path(args.new_behavior_summary))
    old_matrix = load_yaml(Path(args.old_render_matrix))
    new_matrix = load_yaml(Path(args.new_render_matrix))
    old_run_rows = read_jsonl(Path(args.old_run_jsonl))
    new_run_rows = read_jsonl(Path(args.new_run_jsonl))

    old_verdicts = verdict_counts(old_summary)
    new_verdicts = verdict_counts(new_summary)
    old_behavior_counts = verdict_counts(old_behavior)
    new_behavior_counts = verdict_counts(new_behavior)

    old_value_counts = value_counts(case_values(old_matrix))
    new_value_counts = value_counts(case_values(new_matrix))
    upweighted = guidance_values(new_matrix, "upweighted_values")
    downweighted = guidance_values(new_matrix, "downweighted_values")

    return {
        "inputs": {
            "old_summary": args.old_summary,
            "new_summary": args.new_summary,
            "old_behavior_summary": args.old_behavior_summary,
            "new_behavior_summary": args.new_behavior_summary,
            "old_render_matrix": args.old_render_matrix,
            "new_render_matrix": args.new_render_matrix,
        },
        "old_total_cases": old_summary.get("total_cases"),
        "new_total_cases": new_summary.get("total_cases"),
        "old_raw_status_counts": status_counts(old_run_rows),
        "new_raw_status_counts": status_counts(new_run_rows),
        "old_verdict_counts": old_verdicts,
        "new_verdict_counts": new_verdicts,
        "old_behavior_verdict_counts": old_behavior_counts,
        "new_behavior_verdict_counts": new_behavior_counts,
        "unexpected_success_delta": count_delta(
            new_verdicts,
            old_verdicts,
            "unexpected_success_candidate",
        ),
        "crash_delta": count_delta(
            new_verdicts,
            old_verdicts,
            "sanitizer_crash",
            "crash_candidate",
        ),
        "safe_negative_delta": count_delta(
            new_behavior_counts,
            old_behavior_counts,
            "safe_negative",
        ),
        "repair_queue_delta": repair_count(Path(args.new_repair_queue)) - repair_count(Path(args.old_repair_queue)),
        "feedback_guided_changes": {
            "old_feedback_guided": bool(old_matrix.get("feedback_guided")),
            "new_feedback_guided": bool(new_matrix.get("feedback_guided")),
            "upweighted_values": upweighted,
            "downweighted_values": downweighted,
            "upweighted_values_exercised": count_guided_values(new_value_counts, upweighted),
            "downweighted_values_exercised": count_guided_values(new_value_counts, downweighted),
            "upweighted_value_deltas": compare_guided_counts(old_value_counts, new_value_counts, upweighted),
            "downweighted_value_deltas": compare_guided_counts(old_value_counts, new_value_counts, downweighted),
        },
        "notes": [
            "Comparison is based on summary JSON, behavior novelty JSON, repair queues, and render_matrix value coverage.",
            "safe_negative is treated as a stable safe baseline, not as a vulnerability candidate.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare two mutation sprint result sets.")
    parser.add_argument("--old-summary", required=True)
    parser.add_argument("--new-summary", required=True)
    parser.add_argument("--old-behavior-summary", required=True)
    parser.add_argument("--new-behavior-summary", required=True)
    parser.add_argument("--old-run-jsonl", required=True)
    parser.add_argument("--new-run-jsonl", required=True)
    parser.add_argument("--old-render-matrix", required=True)
    parser.add_argument("--new-render-matrix", required=True)
    parser.add_argument("--old-repair-queue", required=True)
    parser.add_argument("--new-repair-queue", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    comparison = build_comparison(args)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(comparison, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"[OK] comparison written to {out}")
    print(f"[INFO] old_verdict_counts: {comparison['old_verdict_counts']}")
    print(f"[INFO] new_verdict_counts: {comparison['new_verdict_counts']}")
    print(f"[INFO] unexpected_success_delta: {comparison['unexpected_success_delta']}")
    print(f"[INFO] repair_queue_delta: {comparison['repair_queue_delta']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
