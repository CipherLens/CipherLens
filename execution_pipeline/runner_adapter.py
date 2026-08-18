"""Canonical RunSpec/RunRecord adapter."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import (
    BuildResult, CollectionStatus, ExecutionAttemptOutcome, ProcessStart,
    REGISTRY_VERSION, SCHEMA_VERSIONS, Termination,
)
from execution_model.registry import validate_artifact_or_raise


def build_run_spec(
    build_spec: Mapping[str, Any], build_record: Mapping[str, Any], *,
    input_artifacts: Sequence[Mapping[str, Any]] = (), argv: Sequence[str] = (),
    environment_profile: Mapping[str, Any], working_directory_profile: Mapping[str, Any],
    timeout_policy: Mapping[str, Any], instrumentation_profile: Mapping[str, Any],
    required_capture_refs: Sequence[str], expected_phases: Sequence[str],
    expected_markers: Sequence[str] = (), required_channels: Sequence[str] = ("stdout", "stderr"),
) -> dict[str, Any]:
    validate_artifact_or_raise(build_spec)
    validate_artifact_or_raise(build_record)
    if build_record.get("result") != BuildResult.BUILT.value:
        raise ValueError("RunSpec requires BUILT BuildRecord")
    if build_record.get("build_spec_ref") != build_spec.get("build_spec_id") or build_record.get("build_spec_digest") != artifact_digest(build_spec):
        raise ValueError("BuildRecord does not belong to BuildSpec")
    document = identify({
        "schema_version": SCHEMA_VERSIONS["run_spec"], "run_spec_id": "pending",
        "build_spec_ref": build_spec["build_spec_id"], "build_spec_digest": artifact_digest(build_spec),
        "build_record_ref": build_record["build_record_id"], "build_record_digest": artifact_digest(build_record),
        "binary_ref": build_record["binary_ref"], "binary_digest": build_record["binary_digest"],
        "input_artifacts": [dict(x) for x in input_artifacts], "argv": list(argv),
        "environment_profile": dict(environment_profile), "working_directory_profile": dict(working_directory_profile),
        "timeout_policy": dict(timeout_policy), "instrumentation_profile": dict(instrumentation_profile),
        "required_capture_refs": list(required_capture_refs), "expected_phases": list(expected_phases),
        "expected_markers": list(expected_markers), "required_channels": list(required_channels),
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document)
    return document


def execute_run(
    run_spec: Mapping[str, Any], *, binary_path: Path, controlled_env: Mapping[str, str],
    working_directory: Path, timeout_seconds: int, runner: Callable[..., Any] = subprocess.run,
) -> tuple[dict[str, Any], dict[str, Any]]:
    validate_artifact_or_raise(run_spec)
    if not binary_path.is_file():
        raise FileNotFoundError("RunSpec binary is missing")
    if hashlib.sha256(binary_path.read_bytes()).hexdigest() != run_spec["binary_digest"]:
        raise ValueError("RunSpec binary integrity mismatch")
    command = [str(binary_path), *run_spec["argv"]]
    start = ProcessStart.STARTED.value
    termination = Termination.EXITED.value
    collection = CollectionStatus.COMPLETE.value
    exit_status = None
    signal = None
    timed_out = False
    stdout = b""
    stderr = b""
    reasons: list[str] = []
    try:
        completed = runner(command, text=True, capture_output=True, timeout=timeout_seconds, env=dict(controlled_env), cwd=working_directory, check=False)
        exit_status = completed.returncode if completed.returncode >= 0 else None
        signal = -completed.returncode if completed.returncode < 0 else None
        termination = Termination.SIGNALED.value if completed.returncode < 0 else Termination.EXITED.value
        stdout = (completed.stdout or "").encode("utf-8", errors="replace")
        stderr = (completed.stderr or "").encode("utf-8", errors="replace")
    except FileNotFoundError:
        start = ProcessStart.LAUNCH_FAILED.value
        termination = Termination.NOT_STARTED.value
        collection = CollectionStatus.FAILED.value
        reasons.append("RUN_LAUNCH_FAILED")
    except subprocess.TimeoutExpired as exc:
        termination = Termination.TIMED_OUT.value
        collection = CollectionStatus.PARTIAL.value
        timed_out = True
        stdout = (exc.stdout or "").encode("utf-8", errors="replace") if isinstance(exc.stdout, str) else (exc.stdout or b"")
        stderr = (exc.stderr or "").encode("utf-8", errors="replace") if isinstance(exc.stderr, str) else (exc.stderr or b"")
        reasons.append("RUN_TIMED_OUT")
    raw = [
        {"artifact_ref": "raw:run.stdout", "artifact_digest": hashlib.sha256(stdout).hexdigest(), "media_type": "text/plain"},
        {"artifact_ref": "raw:run.stderr", "artifact_digest": hashlib.sha256(stderr).hexdigest(), "media_type": "text/plain"},
    ]
    events = [{"evidence_id": "process:event:termination", "evidence_type": "timeout" if timed_out else "process_exit", "artifact_refs": [x["artifact_ref"] for x in raw]}] if start == "STARTED" else []
    record = identify({
        "schema_version": SCHEMA_VERSIONS["run_record"], "run_record_id": "pending",
        "run_spec_ref": run_spec["run_spec_id"], "run_spec_digest": artifact_digest(run_spec),
        "binary_ref": run_spec["binary_ref"], "binary_digest": run_spec["binary_digest"],
        "process_start": start, "termination": termination, "collection": collection,
        "exit_status": exit_status, "signal": signal, "timeout": timed_out,
        "raw_artifacts": raw, "process_events": events, "raw_observations": [],
        "integrity_reasons": reasons, "telemetry_ref": "telemetry:run",
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(record)
    return record, {"command": command, "binary_path": str(binary_path), "working_directory": str(working_directory)}


def attempt_outcome(build_record: Mapping[str, Any] | None, run_record: Mapping[str, Any] | None) -> str:
    if build_record is None:
        return ExecutionAttemptOutcome.BUILD_SPEC_REJECTED.value
    result = build_record.get("result")
    if result == "COMPILE_FAILED": return ExecutionAttemptOutcome.COMPILE_FAILED.value
    if result == "LINK_FAILED": return ExecutionAttemptOutcome.LINK_FAILED.value
    if result == "OUTPUT_MISSING": return ExecutionAttemptOutcome.EXECUTABLE_MISSING.value
    if result != "BUILT": return ExecutionAttemptOutcome.EXECUTOR_FAILURE.value
    if run_record is None: return ExecutionAttemptOutcome.RUN_SPEC_REJECTED.value
    if run_record.get("process_start") != "STARTED": return ExecutionAttemptOutcome.RUN_LAUNCH_FAILED.value
    return ExecutionAttemptOutcome.WITNESS_FORMED.value
