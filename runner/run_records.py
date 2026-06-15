"""Record builders shared by family-level compile/run wrappers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from runner.sanitizer_env import raw_excerpt, rel


def classify_raw_observation(
    compile_success: bool,
    timeout: bool,
    returncode: int | None,
    sanitizer_seen: bool,
) -> str:
    if not compile_success:
        return "compile_failed_not_run"
    if timeout:
        return "timeout_observed"
    if returncode is not None and returncode < 0:
        return "crash_signal_observed"
    if sanitizer_seen:
        return "sanitizer_output_observed"
    if returncode == 0:
        return "normal_exit"
    return "nonzero_exit"


def compile_result_record(
    *,
    case: dict[str, Any],
    harness: Path,
    binary: Path,
    compile_command: str,
    compile_status: str,
    compile_stdout: Path,
    compile_stderr: Path,
    return_code: int | None,
    notes: list[str],
    include_compile_job_id: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {}
    if include_compile_job_id:
        record["compile_job_id"] = case.get("compile_job_id", "")
    record.update(
        {
            "case_id": case.get("case_id", ""),
            "family": case.get("family", ""),
            "mutation_strategy": case.get("mutation_strategy", ""),
            "target_library": case.get("target_library", ""),
            "harness_c": rel(harness),
            "binary_path": rel(binary),
            "compile_command": compile_command,
            "compile_status": compile_status,
            "stdout_log": rel(compile_stdout),
            "stderr_log": rel(compile_stderr),
            "return_code": return_code,
            "notes": notes,
        }
    )
    return record


def run_result_record(
    *,
    case: dict[str, Any],
    binary: Path,
    run_status: str,
    exit_code: int | None,
    signal: str,
    timeout: bool,
    duration_seconds: float,
    run_stdout: Path,
    run_stderr: Path,
    sanitizer_observed: bool,
    sanitizer_kinds: list[str],
    raw_observation_label: str,
    notes: list[str] | None = None,
    oracle_event_count: int | None = None,
    include_compile_job_id: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {}
    if include_compile_job_id:
        record["compile_job_id"] = case.get("compile_job_id", "")
    record.update(
        {
            "case_id": case.get("case_id", ""),
            "family": case.get("family", ""),
            "mutation_strategy": case.get("mutation_strategy", ""),
            "target_library": case.get("target_library", ""),
            "binary_path": rel(binary),
            "run_status": run_status,
            "exit_code": exit_code,
            "signal": signal,
            "timeout": timeout,
            "duration_seconds": round(duration_seconds, 6),
            "stdout_log": rel(run_stdout),
            "stderr_log": rel(run_stderr),
            "sanitizer_observed": sanitizer_observed,
            "sanitizer_kinds": sanitizer_kinds,
            "raw_observation_label": raw_observation_label,
        }
    )
    if oracle_event_count is not None:
        record["oracle_event_count"] = oracle_event_count
    if notes is not None:
        record["notes"] = notes
    return record


def sanitizer_observation_record(
    *,
    case: dict[str, Any],
    sanitizer_observed: bool,
    sanitizer_kinds: list[str],
    matched_keywords: list[str],
    stderr_log: Path,
    combined_output: str,
    include_compile_job_id: bool = True,
) -> dict[str, Any]:
    record: dict[str, Any] = {}
    if include_compile_job_id:
        record["compile_job_id"] = case.get("compile_job_id", "")
    record.update(
        {
            "case_id": case.get("case_id", ""),
            "family": case.get("family", ""),
            "mutation_strategy": case.get("mutation_strategy", ""),
            "sanitizer_observed": sanitizer_observed,
            "sanitizer_kinds": sanitizer_kinds,
            "matched_keywords": matched_keywords,
            "stderr_log": rel(stderr_log),
            "raw_excerpt": raw_excerpt(combined_output),
            "triage_required": True,
            "claim_policy": {
                "confirmed_vulnerability": False,
                "cve": False,
                "exploitable": False,
            },
        }
    )
    return record
