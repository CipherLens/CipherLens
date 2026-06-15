from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def classify(row: dict[str, Any]) -> str:
    if row.get("status") != "run_ok":
        return "harness_error"
    manifest = row.get("manifest") or {}
    run = row.get("run") or {}
    shape = manifest.get("input_shape", "")
    exit_code = int(run.get("exit_code", 1))
    output_created = bool(run.get("output_artifact_created"))
    output_nonempty = bool(run.get("output_artifact_nonempty"))
    accepted = exit_code == 0

    if shape == "valid_der_only":
        return "valid_baseline_success" if accepted and output_created else "harness_error"
    if shape == "malformed_only":
        return "malformed_baseline_reject" if not accepted else "needs_manual_triage"
    if shape == "valid_der_plus_malformed_tail":
        if accepted and output_created and output_nonempty:
            return "app_level_validation_gap_candidate"
        if not accepted:
            return "strict_reject"
        return "needs_manual_triage"
    if shape in {"valid_der_plus_valid_der_object", "valid_der_plus_duplicate_object"}:
        if accepted and output_created:
            return "expected_prefix_accept_behavior"
        if not accepted:
            return "strict_reject"
        return "needs_manual_triage"
    return "needs_manual_triage"


def summarize(verdict_rows: list[dict[str, Any]]) -> dict[str, Any]:
    verdict_counts = Counter(row["verdict"] for row in verdict_rows)
    by_target: dict[str, Counter[str]] = defaultdict(Counter)
    by_shape: dict[str, Counter[str]] = defaultdict(Counter)
    by_tail_len: dict[str, Counter[str]] = defaultdict(Counter)
    by_tail_content: dict[str, Counter[str]] = defaultdict(Counter)
    for row in verdict_rows:
        m = row["manifest"]
        verdict = row["verdict"]
        by_target[str(m.get("parser_target", ""))][verdict] += 1
        by_shape[str(m.get("input_shape", ""))][verdict] += 1
        by_tail_len[str(m.get("trailing_length", ""))][verdict] += 1
        by_tail_content[str(m.get("trailing_content", ""))][verdict] += 1
    return {
        "total_cases": len(verdict_rows),
        "verdict_counts": dict(verdict_counts),
        "by_parser_target": {k: dict(v) for k, v in by_target.items()},
        "by_input_shape": {k: dict(v) for k, v in by_shape.items()},
        "by_trailing_length": {k: dict(v) for k, v in by_tail_len.items()},
        "by_trailing_content": {k: dict(v) for k, v in by_tail_content.items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-output", type=Path, required=True)
    parser.add_argument("--behavior-output", type=Path, required=True)
    parser.add_argument("--novel-output", type=Path, required=True)
    args = parser.parse_args()

    rows = load_jsonl(args.input)
    verdict_rows = []
    for row in rows:
        verdict = classify(row)
        verdict_rows.append(
            {
                "case_id": row.get("case_id"),
                "source": row.get("source"),
                "verdict": verdict,
                "manifest": row.get("manifest") or {},
                "run": {
                    "exit_code": (row.get("run") or {}).get("exit_code"),
                    "output_artifact_created": (row.get("run") or {}).get("output_artifact_created"),
                    "output_artifact_nonempty": (row.get("run") or {}).get("output_artifact_nonempty"),
                    "stderr_excerpt": " ".join(str((row.get("run") or {}).get("stderr", "")).split())[:240],
                },
            }
        )

    summary = summarize(verdict_rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    args.behavior_output.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    with args.case_output.open("w", encoding="utf-8") as f:
        for row in verdict_rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    with args.novel_output.open("w", encoding="utf-8") as f:
        for row in verdict_rows:
            if row["verdict"] == "app_level_validation_gap_candidate":
                f.write(json.dumps(row, sort_keys=True) + "\n")

    print(f"[SUMMARY] total_cases: {summary['total_cases']}")
    print(f"[SUMMARY] verdict_counts: {summary['verdict_counts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
