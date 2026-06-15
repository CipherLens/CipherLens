"""Adapters from sprint compile/run YAML records to existing analyzer verdicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from runner.analyze_results import classify_record


REUSED_MODULES = [
    "runner.analyze_results.classify_record",
    "runner.analyze_results.ASAN_PATTERNS",
    "runner.analyze_results.UBSAN_PATTERNS",
    "runner.analyze_results.BUG_PATTERNS",
    "runner.analyze_results.SAFE_PATTERNS",
]


def read_log(path_value: str) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def run_status_for_existing_analyzer(run: dict[str, Any], compile_result: dict[str, Any]) -> str:
    if compile_result.get("compile_status") != "compile_success":
        return "compile_error"
    if run.get("timeout"):
        return "run_timeout"
    if run.get("run_status") == "exited" and run.get("exit_code") == 0:
        return "run_ok"
    if run.get("run_status") or run.get("exit_code") not in (0, None) or run.get("signal"):
        return "run_nonzero"
    return "unknown"


def to_existing_analyzer_record(run: dict[str, Any], compile_result: dict[str, Any]) -> dict[str, Any]:
    harness_c = str(compile_result.get("harness_c") or "")
    target_library = str(run.get("target_library") or compile_result.get("target_library") or "")
    return {
        "status": run_status_for_existing_analyzer(run, compile_result),
        "source": harness_c,
        "relative_source": harness_c,
        "library": target_library,
        "template": {
            "harness_family": run.get("family") or compile_result.get("family") or "",
            "target_library": target_library,
        },
        "compile": {
            "returncode": compile_result.get("return_code"),
            "stdout": read_log(str(compile_result.get("stdout_log") or "")),
            "stderr": read_log(str(compile_result.get("stderr_log") or "")),
            "timeout": False,
        },
        "run": {
            "returncode": run.get("exit_code"),
            "stdout": read_log(str(run.get("stdout_log") or "")),
            "stderr": read_log(str(run.get("stderr_log") or "")),
            "timeout": bool(run.get("timeout")),
        },
    }


def classify_family_run(run: dict[str, Any], compile_result: dict[str, Any]) -> dict[str, Any]:
    record = to_existing_analyzer_record(run, compile_result)
    verdict = classify_record(record)
    return {
        "reused_existing_pipeline": True,
        "reused_modules": REUSED_MODULES,
        "existing_record_status": record.get("status", ""),
        "existing_verdict": verdict.get("verdict", ""),
        "existing_reason": verdict.get("reason", ""),
        "exit_code": verdict.get("exit_code"),
        "run_timeout": verdict.get("run_timeout", False),
        "compile_returncode": verdict.get("compile_returncode"),
    }


def analysis_label_from_existing(existing: dict[str, Any]) -> str:
    verdict = existing.get("existing_verdict", "")
    if verdict == "build_or_template_error":
        return "compile_failure"
    if verdict == "timeout":
        return "timeout_candidate"
    if verdict in {"sanitizer_crash", "ubsan_crash"}:
        return "sanitizer_crash_candidate"
    if verdict in {"bug_candidate", "unexpected_success_candidate"}:
        return "bug_candidate"
    if verdict in {"nonzero_needs_triage", "harness_input_error"}:
        return "nonzero_exit_candidate"
    if verdict in {
        "normal_behavior_needs_triage",
        "unknown",
        "normal_expected_behavior",
        "safe_behavior",
        "safe_reject_behavior",
        "fixed_behavior",
        "semantic_projection_limitation",
    }:
        return "no_crash_observed"
    return "oracle_semantics_needs_review"


def candidate_label_from_existing(
    existing: dict[str, Any], expected_label: str
) -> tuple[str, str, str, str]:
    label = analysis_label_from_existing(existing)
    verdict = existing.get("existing_verdict", "")
    reason = existing.get("existing_reason", "")
    if label == "sanitizer_crash_candidate":
        return (
            "sanitizer_crash_candidate",
            "high",
            reason or "existing analyzer reported sanitizer/UBSAN crash evidence",
            "manual crash triage and reproduction",
        )
    if label == "bug_candidate":
        return (
            "needs_triage",
            "medium",
            reason or "existing analyzer reported a bug-like oracle signal",
            "manual semantic triage before any vulnerability claim",
        )
    if label == "timeout_candidate":
        return ("needs_triage", "medium", reason or "case timed out", "timeout triage")
    if label == "nonzero_exit_candidate":
        return (
            "needs_triage",
            "medium",
            reason or "nonzero or harness input error observed",
            "inspect harness oracle semantics",
        )
    if label == "compile_failure":
        return ("needs_triage", "high", reason or "case did not compile", "compile fixup")
    if expected_label in {"semantic_divergence_candidate", "needs_triage", "api_misuse_false_positive"}:
        return (
            "no_crash_observed",
            "high",
            "existing analyzer found no crash/sanitizer evidence; semantic oracle still needs review for expected label",
            "semantic oracle review only if needed",
        )
    return (
        "no_crash_observed",
        "high",
        "existing analyzer found no crash/sanitizer evidence in raw execution",
        "semantic oracle review only if needed",
    )
