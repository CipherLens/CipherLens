"""Behavior novelty analyzer v0.

This module clusters existing runner JSONL and app-level command matrices into
coarse discovery labels. It is intentionally conservative: nonzero harness exits
are not treated as crashes unless sanitizer or SEGV evidence is present.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


CRASH_PATTERNS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "SEGV",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "runtime error:",
)


def _read_jsonl(path: Optional[Path]) -> Iterable[Dict[str, Any]]:
    if not path:
        return
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "accepted"}


def _text_tags(text: str) -> List[str]:
    tags: List[str] = []
    lowered = text.lower()
    if "-----begin" in lowered:
        tags.append("pem_object")
    if "fingerprint=" in lowered or "sha1 fingerprint" in lowered:
        tags.append("fingerprint")
    if "public key" in lowered or "-----begin public key" in lowered:
        tags.append("public_key")
    if "certificate request" in lowered:
        tags.append("csr_text")
    if "certificate revocation list" in lowered or "last update" in lowered:
        tags.append("crl_text")
    if "[bug]" in lowered:
        tags.append("oracle_bug_marker")
    if "[ok]" in lowered:
        tags.append("oracle_ok_marker")
    return tags


def _sanitizer_signal(exit_code: Optional[int], stdout: str, stderr: str) -> str:
    combined = f"{stdout}\n{stderr}"
    for pattern in CRASH_PATTERNS:
        if pattern in combined:
            return pattern
    if exit_code == 139:
        return "exit_139_segv"
    return ""


def _extract_int(pattern: str, text: str) -> Optional[int]:
    match = re.search(pattern, text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _classify_runner_case(obj: Dict[str, Any]) -> Tuple[str, str]:
    status = str(obj.get("status") or obj.get("raw_status") or "")
    verdict = str(obj.get("verdict") or "")
    stdout = str((obj.get("run") or {}).get("stdout") or obj.get("stdout") or "")
    stderr = str((obj.get("run") or {}).get("stderr") or obj.get("stderr") or "")
    exit_code = (obj.get("run") or {}).get("returncode", obj.get("exit_code"))
    compile_stderr = str((obj.get("compile") or {}).get("stderr") or "")
    sanitizer = _sanitizer_signal(exit_code, stdout, stderr)

    if sanitizer:
        return "crash_candidate", f"crash signal: {sanitizer}"
    if "compile_error" in status or (obj.get("compile") or {}).get("returncode") not in (None, 0):
        if "undefined reference" in compile_stderr or "ld:" in compile_stderr:
            return "harness_error", "link-like compile failure"
        return "harness_error", "compile failure"
    if "render_error" in status or "template_render_error" in status:
        return "harness_error", "template render failure"
    if verdict in {"safe_reject_behavior", "migrated_safe"}:
        return "safe_negative", verdict
    if verdict in {"bug_candidate", "migrated_bug_candidate"}:
        if "consumed_len" in stdout and "der_len" in stdout:
            return "low_level_d2i_prefix_parse", "pointer-consumption oracle"
        return "semantic_candidate", verdict
    if "normal_behavior_needs_triage" in verdict or "triage" in verdict:
        return "unknown_needs_triage", verdict
    if status == "run_ok":
        return "safe_negative", "run_ok without novelty marker"
    return "unknown_needs_triage", status or verdict or "unclassified"


def _command_has_issue_grade_output(row: Dict[str, Any]) -> bool:
    name = str(row.get("command_name") or "").lower()
    command = str(row.get("command") or "").lower()
    if any(token in name for token in ("fingerprint", "export", "convert", "pubout", "pubkey", "text")):
        return True
    if any(token in command for token in ("-fingerprint", "-outform pem", "-pubout", "-pubkey", "-text")):
        return True
    return _bool(row.get("output_file_nonempty")) or _bool(row.get("stdout_nonempty"))


def _read_command_rows(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _classify_command_rows(rows: List[Dict[str, Any]]) -> Dict[Tuple[str, str], str]:
    groups: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        groups[(str(row.get("input_kind") or ""), str(row.get("command_name") or ""))][
            str(row.get("input_case") or "")
        ] = row

    group_classes: Dict[Tuple[str, str], str] = {}
    for key, cases in groups.items():
        baseline = cases.get("baseline")
        tail = cases.get("tail")
        malformed = cases.get("malformed_only")
        baseline_ok = bool(baseline) and _bool(baseline.get("accepted", baseline.get("accepted_rejected")))
        tail_ok = bool(tail) and _bool(tail.get("accepted", tail.get("accepted_rejected")))
        malformed_rejected = bool(malformed) and not _bool(
            malformed.get("accepted", malformed.get("accepted_rejected"))
        )
        if baseline_ok and tail_ok and malformed_rejected:
            if tail and _command_has_issue_grade_output(tail):
                group_classes[key] = "real_app_level_validation_gap_candidate"
            else:
                group_classes[key] = "app_level_accepts_valid_prefix_with_malformed_tail"
        elif tail_ok:
            group_classes[key] = "app_command_accepts_malformed_tail"
        elif baseline_ok and malformed_rejected:
            group_classes[key] = "safe_negative"
        else:
            group_classes[key] = "unknown_needs_triage"
    return group_classes


def _case_from_command_row(
    row: Dict[str, Any], artifact: str, group_class: str
) -> Dict[str, Any]:
    stdout_tags = ["stdout_nonempty"] if _bool(row.get("stdout_nonempty")) else []
    stderr_tags = ["stderr_nonempty"] if _bool(row.get("stderr_nonempty")) else []
    if row.get("stderr_excerpt"):
        stderr_tags.extend(_text_tags(str(row.get("stderr_excerpt"))))
    input_case = str(row.get("input_case") or "")
    row_verdict = str(row.get("verdict") or "")
    if input_case == "tail" and group_class == "real_app_level_validation_gap_candidate":
        verdict = group_class
    elif input_case == "tail" and group_class == "app_level_accepts_valid_prefix_with_malformed_tail":
        verdict = group_class
    elif row_verdict:
        verdict = row_verdict
    else:
        verdict = group_class
    return {
        "case_id": str(row.get("command_id") or ""),
        "artifact": artifact,
        "library": "openssl",
        "api_or_command": str(row.get("command_name") or row.get("command") or ""),
        "input_kind": str(row.get("input_kind") or ""),
        "mutation": input_case,
        "exit_code": int(row.get("exit_code") or 0),
        "verdict": verdict,
        "migration_verdict": "",
        "stdout_tags": stdout_tags,
        "stderr_tags": stderr_tags,
        "sanitizer_signal": "",
        "consumed_len": None,
        "trailing_len": None,
        "caller_accept": _bool(row.get("accepted", row.get("accepted_rejected"))),
        "output_file_created": _bool(row.get("output_file_created")),
        "output_file_nonempty": _bool(row.get("output_file_nonempty")),
    }


def _case_from_runner_obj(obj: Dict[str, Any], artifact: str) -> Dict[str, Any]:
    stdout = str((obj.get("run") or {}).get("stdout") or obj.get("stdout") or "")
    stderr = str((obj.get("run") or {}).get("stderr") or obj.get("stderr") or "")
    exit_code = (obj.get("run") or {}).get("returncode", obj.get("exit_code"))
    classification, _reason = _classify_runner_case(obj)
    consumed_len = _extract_int(r"consumed_len=(\d+)", stdout)
    der_len = _extract_int(r"der_len=(\d+)", stdout)
    trailing_len = None
    if consumed_len is not None and der_len is not None:
        trailing_len = max(der_len - consumed_len, 0)
    return {
        "case_id": str(obj.get("relative_source") or obj.get("source") or ""),
        "artifact": artifact,
        "library": str(obj.get("library") or ""),
        "api_or_command": str(obj.get("target_api") or (obj.get("template") or {}).get("target_api") or ""),
        "input_kind": str((obj.get("mutation_mapping") or {}).get("[DER_KIND]") or ""),
        "mutation": str((obj.get("mutation_mapping") or {}).get("[TRAILING_GARBAGE_BYTES]") or ""),
        "exit_code": exit_code,
        "verdict": classification,
        "migration_verdict": str(obj.get("migration_verdict") or ""),
        "stdout_tags": _text_tags(stdout),
        "stderr_tags": _text_tags(stderr),
        "sanitizer_signal": _sanitizer_signal(exit_code, stdout, stderr),
        "consumed_len": consumed_len,
        "trailing_len": trailing_len,
        "caller_accept": classification not in {"safe_negative", "harness_error"},
        "output_file_created": False,
        "output_file_nonempty": False,
    }


def analyze(args: argparse.Namespace) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    cases: List[Dict[str, Any]] = []

    verdict_by_case: Dict[str, Dict[str, Any]] = {}
    if args.verdicts_jsonl:
        for obj in _read_jsonl(args.verdicts_jsonl):
            key = str(obj.get("relative_source") or obj.get("source") or "")
            if key:
                verdict_by_case[key] = obj

    if args.run_jsonl:
        for obj in _read_jsonl(args.run_jsonl):
            key = str(obj.get("relative_source") or obj.get("source") or "")
            if key and key in verdict_by_case:
                merged = dict(obj)
                verdict_obj = verdict_by_case[key]
                for field in ("verdict", "migration_verdict", "reason", "raw_status"):
                    if field in verdict_obj:
                        merged[field] = verdict_obj[field]
                cases.append(_case_from_runner_obj(merged, str(args.run_jsonl)))
            else:
                cases.append(_case_from_runner_obj(obj, str(args.run_jsonl)))
    elif args.verdicts_jsonl:
        for obj in verdict_by_case.values():
            cases.append(_case_from_runner_obj(obj, str(args.verdicts_jsonl)))

    if args.command_matrix_csv:
        rows = _read_command_rows(args.command_matrix_csv)
        group_classes = _classify_command_rows(rows)
        for row in rows:
            key = (str(row.get("input_kind") or ""), str(row.get("command_name") or ""))
            cases.append(_case_from_command_row(row, str(args.command_matrix_csv), group_classes[key]))

    verdict_counts = Counter(str(case.get("verdict") or "unknown_needs_triage") for case in cases)
    summary = {
        "inputs": {
            "run_jsonl": str(args.run_jsonl) if args.run_jsonl else "",
            "verdicts_jsonl": str(args.verdicts_jsonl) if args.verdicts_jsonl else "",
            "command_matrix_csv": str(args.command_matrix_csv) if args.command_matrix_csv else "",
        },
        "total_cases": len(cases),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "has_crash_candidate": verdict_counts.get("crash_candidate", 0) > 0,
        "has_real_app_level_validation_gap_candidate": verdict_counts.get(
            "real_app_level_validation_gap_candidate", 0
        )
        > 0,
    }
    return summary, cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze behavior novelty from existing results.")
    parser.add_argument("--run-jsonl", type=Path)
    parser.add_argument("--verdicts-jsonl", type=Path)
    parser.add_argument("--command-matrix-csv", type=Path)
    parser.add_argument("--out-summary", type=Path, required=True)
    parser.add_argument("--out-cases", type=Path, required=True)
    args = parser.parse_args()

    if not any((args.run_jsonl, args.verdicts_jsonl, args.command_matrix_csv)):
        parser.error("provide at least one input: --run-jsonl, --verdicts-jsonl, or --command-matrix-csv")

    summary, cases = analyze(args)
    args.out_summary.parent.mkdir(parents=True, exist_ok=True)
    args.out_cases.parent.mkdir(parents=True, exist_ok=True)
    args.out_summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with args.out_cases.open("w", encoding="utf-8") as f:
        for case in cases:
            f.write(json.dumps(case, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
