import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


ALLOWED_LABELS = {
    "normal_control_ok",
    "normal_control_failed",
    "expected_reject",
    "permissive_behavior",
    "semantic_divergence_candidate",
    "crash_candidate",
    "sanitizer_needed",
    "harness_error",
    "compile_error",
    "needs_triage",
}

CRASH_PATTERNS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "heap-use-after-free",
    "use-after-free",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "runtime error:",
    "SEGV",
    "SIGSEGV",
]


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_manifest(source: str) -> Dict[str, Any]:
    if not source:
        return {}
    src = Path(source)
    manifest = src.parent / "case_manifest.yaml"
    if not manifest.exists():
        return {}
    with manifest.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def extract_stdout(record: Dict[str, Any]) -> str:
    run = record.get("run") or {}
    return run.get("stdout") or record.get("stdout") or ""


def extract_stderr(record: Dict[str, Any]) -> str:
    run = record.get("run") or {}
    compile_info = record.get("compile") or {}
    return "\n".join(
        part
        for part in [
            run.get("stderr") or record.get("stderr") or "",
            compile_info.get("stderr") or "",
        ]
        if part
    )


def extract_returncode(record: Dict[str, Any]) -> Optional[int]:
    run = record.get("run") or {}
    for key in ("returncode", "exit_code", "exitcode"):
        if key in run:
            return run.get(key)
        if key in record:
            return record.get(key)
    return None


def extract_case_result(stdout: str) -> str:
    match = re.search(r"^CASE_RESULT=([A-Za-z0-9_]+)\s*$", stdout, re.MULTILINE)
    return match.group(1) if match else ""


def has_crash_evidence(record: Dict[str, Any], stdout: str, stderr: str) -> bool:
    status = str(record.get("status") or "")
    rc = extract_returncode(record)
    combined = stdout + "\n" + stderr
    if any(pattern in combined for pattern in CRASH_PATTERNS):
        return True
    if rc is not None and (rc < 0 or rc == 139 or rc >= 128):
        return True
    return "crash" in status.lower()


def classify(record: Dict[str, Any], manifest: Dict[str, Any]) -> Dict[str, Any]:
    stdout = extract_stdout(record)
    stderr = extract_stderr(record)
    case_result = extract_case_result(stdout)
    status = str(record.get("status") or "")
    case_type = manifest.get("case_type") or ""
    case_name = manifest.get("case_name") or ""
    rc = extract_returncode(record)

    if status == "compile_error":
        label = "compile_error"
        observed = "compile_error"
        next_action = "fix_harness_or_build_config_before_semantic_interpretation"
    elif has_crash_evidence(record, stdout, stderr):
        label = "crash_candidate"
        observed = "explicit_crash_or_sanitizer_evidence"
        next_action = "inspect_sanitizer_output_and_confirm_against_debug_build"
    elif status in {"run_timeout", "timeout"}:
        label = "harness_error"
        observed = "run_timeout"
        next_action = "check_harness_timeout_or_library_hang"
    elif case_result == "harness_error":
        label = "harness_error"
        observed = "harness_reported_error"
        next_action = "repair_control_flow_or_initialization_before_interpretation"
    elif case_type == "safety_control":
        if case_result == "ok" and (rc == 0 or rc is None):
            label = "normal_control_ok"
            observed = "normal_control_completed"
            next_action = "use_as_baseline_for_mutation_cases"
        else:
            label = "normal_control_failed"
            observed = case_result or status or "control_failed"
            next_action = "stop_mutation_interpretation_until_controls_pass"
    elif case_result == "expected_reject":
        label = "expected_reject"
        observed = "mutation_rejected_by_api"
        next_action = "record_as_strict_or_safe_reject_behavior"
    elif case_result == "permissive_behavior":
        if case_name in {"wrong_tag_length", "final_without_update"}:
            label = "semantic_divergence_candidate"
            observed = "mutation_allowed_but_may_match_documented_low_level_semantics"
            next_action = "compare_against API documentation and other AEAD implementations"
        else:
            label = "permissive_behavior"
            observed = "mutation_allowed_by_api"
            next_action = "prioritize for cross-library comparison, not as confirmed bug"
    elif "Sanitizer" in stderr or "runtime error:" in stderr:
        label = "sanitizer_needed"
        observed = "sanitizer_signal_without_clear_crash_classification"
        next_action = "rerun with focused sanitizer/debug instrumentation"
    else:
        label = "needs_triage"
        observed = case_result or status or "unclassified_behavior"
        next_action = "inspect stdout stderr and strengthen oracle"

    if label not in ALLOWED_LABELS:
        label = "needs_triage"

    return {
        "classification": label,
        "observed_behavior": observed,
        "case_result": case_result,
        "next_action": next_action,
    }


def is_high_value(item: Dict[str, Any], controls_ok: bool) -> bool:
    if item["classification"] == "crash_candidate":
        return True
    if not controls_ok:
        return False
    if item.get("case_type") != "mutation_case":
        return False
    return item["classification"] in {
        "permissive_behavior",
        "semantic_divergence_candidate",
        "needs_triage",
        "sanitizer_needed",
    }


def build_markdown(report: Dict[str, Any]) -> str:
    lines = [
        "# Cipher AEAD Lifecycle Mutation Analysis",
        "",
        "## Summary",
        "",
        f"- total_cases: {report['summary']['total_cases']}",
        f"- raw_status_counts: `{report['summary']['raw_status_counts']}`",
        f"- classification_counts: `{report['summary']['classification_counts']}`",
        f"- normal_controls_passed: {report['summary']['normal_controls_passed']}",
        f"- high_value_candidates: {len(report['high_value_candidates'])}",
        "",
        "## Cases",
        "",
        "| case_id | case_name | type | status | exit | classification | observed |",
        "|---|---|---|---|---:|---|---|",
    ]
    for item in report["cases"]:
        lines.append(
            "| {case_id} | {case_name} | {case_type} | {status} | {exit_code} | "
            "{classification} | {observed_behavior} |".format(**item)
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "这些标签只表示 harness 观察到的 API 状态机行为；`permissive_behavior` 和 "
            "`semantic_divergence_candidate` 都不是漏洞确认。需要跨库对照、文档语义核查和更强 oracle "
            "之后，才能决定是否进入更深层的模式迁移或版本复现。",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--analysis-json", required=True)
    parser.add_argument("--analysis-md", required=True)
    parser.add_argument("--summary-json", required=True)
    parser.add_argument("--summary-md", required=True)
    parser.add_argument("--raw-stdout-dir", required=True)
    parser.add_argument("--raw-stderr-dir", required=True)
    parser.add_argument("--exit-codes", required=True)
    parser.add_argument("--feedback-output", required=True)
    parser.add_argument("--high-value-yaml", required=True)
    parser.add_argument("--high-value-md", required=True)
    args = parser.parse_args()

    records = load_jsonl(Path(args.input))
    cases: List[Dict[str, Any]] = []
    raw_status_counts: Counter[str] = Counter()
    classification_counts: Counter[str] = Counter()
    exit_codes: Dict[str, Any] = {}

    stdout_dir = Path(args.raw_stdout_dir)
    stderr_dir = Path(args.raw_stderr_dir)
    stdout_dir.mkdir(parents=True, exist_ok=True)
    stderr_dir.mkdir(parents=True, exist_ok=True)

    for index, record in enumerate(records):
        manifest = load_manifest(record.get("source") or "")
        case_id = manifest.get("case_id") or Path(record.get("source") or f"case_{index}").stem
        stdout = extract_stdout(record)
        stderr = extract_stderr(record)
        rc = extract_returncode(record)
        result = classify(record, manifest)
        raw_status_counts[str(record.get("status") or "unknown")] += 1
        classification_counts[result["classification"]] += 1
        write_text(stdout_dir / f"{case_id}.stdout.txt", stdout)
        write_text(stderr_dir / f"{case_id}.stderr.txt", stderr)
        exit_codes[case_id] = rc
        cases.append(
            {
                "family": manifest.get("family") or "cipher_aead_lifecycle",
                "case_id": case_id,
                "case_name": manifest.get("case_name") or "",
                "algorithm": manifest.get("algorithm") or "",
                "mode": manifest.get("mode") or "",
                "state_sequence": manifest.get("state_sequence") or "",
                "case_type": manifest.get("case_type") or "",
                "expected_oracle": manifest.get("expected_oracle") or "",
                "source": record.get("source") or "",
                "status": record.get("status") or "",
                "exit_code": rc,
                **result,
            }
        )

    normal_controls = [c for c in cases if c.get("case_type") == "safety_control"]
    controls_ok = bool(normal_controls) and all(
        c["classification"] == "normal_control_ok" for c in normal_controls
    )
    high_value = [c for c in cases if is_high_value(c, controls_ok)]
    report = {
        "summary": {
            "total_cases": len(cases),
            "raw_status_counts": dict(raw_status_counts),
            "classification_counts": dict(classification_counts),
            "normal_controls_passed": controls_ok,
        },
        "cases": cases,
        "high_value_candidates": high_value,
        "notes": [
            "No confirmed vulnerability claim is made by this analyzer.",
            "permissive_behavior and semantic_divergence_candidate require documentation and cross-library review.",
        ],
    }

    write_json(Path(args.analysis_json), report)
    write_text(Path(args.analysis_md), build_markdown(report))
    write_json(
        Path(args.summary_json),
        {
            "total_cases": len(cases),
            "raw_status_counts": dict(raw_status_counts),
            "classification_counts": dict(classification_counts),
            "normal_controls_passed": controls_ok,
            "high_value_candidate_count": len(high_value),
        },
    )
    write_text(
        Path(args.summary_md),
        "\n".join(
            [
                "# Compile Run Summary",
                "",
                f"- total_cases: {len(cases)}",
                f"- raw_status_counts: `{dict(raw_status_counts)}`",
                f"- classification_counts: `{dict(classification_counts)}`",
                f"- normal_controls_passed: {controls_ok}",
                f"- high_value_candidate_count: {len(high_value)}",
                "",
            ]
        ),
    )
    write_json(Path(args.exit_codes), exit_codes)
    Path(args.feedback_output).parent.mkdir(parents=True, exist_ok=True)
    with Path(args.feedback_output).open("w", encoding="utf-8") as f:
        for item in cases:
            f.write(json.dumps(item, sort_keys=True) + "\n")
    Path(args.high_value_yaml).parent.mkdir(parents=True, exist_ok=True)
    Path(args.high_value_yaml).write_text(
        yaml.safe_dump({"high_value_candidates": high_value}, sort_keys=False),
        encoding="utf-8",
    )
    write_text(
        Path(args.high_value_md),
        "\n".join(
            [
                "# High Value AEAD Lifecycle Candidates",
                "",
                *[
                    f"- {item['case_id']} `{item['case_name']}`: {item['classification']} "
                    f"({item['observed_behavior']})"
                    for item in high_value
                ],
                "",
            ]
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
