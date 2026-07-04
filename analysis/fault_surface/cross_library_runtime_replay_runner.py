"""Runtime truth matrix builder for same-seed cross-library replay."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import subprocess
from typing import Any


REQUIRED_LIBRARIES = ("openssl", "mbedtls", "wolfssl", "botan")
OBSERVABLE_FIELDS = (
    "return_code",
    "success",
    "signature_validity",
    "signature_valid",
    "verification_result",
    "key_usage_result",
    "lifecycle_state",
    "accepted_or_rejected",
)


class CrossLibraryRuntimeReplayRunner:
    """Build runtime observations from commands or existing ASAN/UBSAN traces."""

    schema = "cross_library_runtime_replay_runner_v1"

    def replay(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        seed_id = str(seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed")
        commands = _runtime_commands(seed_context)
        existing_traces = _collect_existing_traces(seed_context, security_candidate)
        rows = []
        runtime_executed = False
        for library in REQUIRED_LIBRARIES:
            command = commands.get(library)
            if command:
                row = _execute_replay_command(library, seed_id, command)
                runtime_executed = True
            else:
                row = _row_from_existing_trace(library, seed_id, existing_traces)
            rows.append(row)
        matrix = {
            "schema": "runtime_truth_matrix_v1",
            "seed_id": seed_id,
            "required_libraries": list(REQUIRED_LIBRARIES),
            "asan_ubsan_build_required": True,
            "same_seed_replay": all(row.get("same_seed") for row in rows if row.get("trace_found")),
            "identical_input_across_libraries": _identical_input(rows),
            "runtime_executed_by_this_layer": runtime_executed,
            "mutation_executed": False,
            "pressure_injection_executed": False,
            "trigger_modification_executed": False,
            "rows": rows,
            "status": _matrix_status(rows, runtime_executed),
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "runtime_truth_matrix": matrix,
            "candidate_queue_written": False,
        }


def replay(seed_context: Mapping[str, Any], security_candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run same-seed runtime replay if commands are supplied."""

    return CrossLibraryRuntimeReplayRunner().replay(seed_context, security_candidate)


def _runtime_commands(seed_context: Mapping[str, Any]) -> dict[str, Sequence[str]]:
    raw = seed_context.get("runtime_replay_commands") or {}
    if not isinstance(raw, Mapping):
        return {}
    commands: dict[str, Sequence[str]] = {}
    for key, value in raw.items():
        library = str(key).split("-", 1)[0].lower()
        if isinstance(value, str):
            commands[library] = [value]
        elif isinstance(value, Sequence):
            commands[library] = [str(part) for part in value]
    return commands


def _collect_existing_traces(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    traces: list[Mapping[str, Any]] = []
    for source in (seed_context, security_candidate):
        for key in ("runtime_results", "runtime_traces", "execution_traces", "oracle_results", "observations"):
            traces.extend(_as_trace_list(source.get(key)))
    return traces


def _as_trace_list(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        for key in ("results", "items", "run_results", "observations", "analysis", "traces"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, Mapping)]
        return [value]
    return []


def _execute_replay_command(library: str, seed_id: str, command: Sequence[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "library": library,
            "trace_found": True,
            "same_seed": True,
            "input_identity": seed_id,
            "runtime_source": "executed_replay_command",
            "return_code": completed.returncode,
            "success": completed.returncode == 0,
            "signature_validity": _extract_value(completed.stdout, "signature_validity"),
            "lifecycle_state": _extract_value(completed.stdout, "lifecycle_state"),
            "stdout_excerpt": completed.stdout[:400],
            "stderr_excerpt": completed.stderr[:400],
            "runtime_status": "executed",
        }
    except Exception as exc:  # pragma: no cover - defensive for caller-provided commands.
        return {
            "library": library,
            "trace_found": False,
            "same_seed": False,
            "runtime_source": "executed_replay_command",
            "runtime_status": "execution_failed",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def _row_from_existing_trace(library: str, seed_id: str, traces: list[Mapping[str, Any]]) -> dict[str, Any]:
    trace = _find_library_trace(library, traces)
    if trace is None:
        return {
            "library": library,
            "trace_found": False,
            "same_seed": False,
            "input_identity": "missing_trace",
            "runtime_source": "missing",
            "return_code": None,
            "success": None,
            "signature_validity": None,
            "lifecycle_state": None,
            "runtime_status": "blocked_missing_runtime_replay_command",
        }
    trace_seed = str(trace.get("seed_id") or trace.get("seed_candidate_id") or seed_id)
    return {
        "library": library,
        "trace_found": True,
        "same_seed": trace_seed == seed_id,
        "input_identity": trace_seed,
        "runtime_source": "existing_asan_ubsan_trace",
        "return_code": trace.get("return_code"),
        "success": _success(trace),
        "signature_validity": trace.get("signature_validity")
        or trace.get("signature_valid")
        or trace.get("verification_result"),
        "lifecycle_state": trace.get("lifecycle_state"),
        "key_usage_result": trace.get("key_usage_result"),
        "runtime_status": "existing_trace_used" if trace_seed == seed_id else "blocked_seed_mismatch",
    }


def _find_library_trace(library: str, traces: list[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    for trace in traces:
        target = str(
            trace.get("target_library")
            or trace.get("library")
            or trace.get("target")
            or trace.get("target_name")
            or ""
        ).lower()
        if target.startswith(library):
            return trace
    return None


def _success(trace: Mapping[str, Any]) -> bool | None:
    if "success" in trace:
        return bool(trace.get("success"))
    if "return_code" in trace:
        return int(trace.get("return_code") or 0) == 0
    accepted = trace.get("accepted_or_rejected")
    if accepted is not None:
        return bool(accepted)
    return None


def _identical_input(rows: list[Mapping[str, Any]]) -> bool:
    identities = {row.get("input_identity") for row in rows if row.get("trace_found")}
    return len(identities) == 1 and bool(identities)


def _matrix_status(rows: list[Mapping[str, Any]], runtime_executed: bool) -> str:
    if any(not row.get("trace_found") for row in rows):
        return "blocked_missing_runtime_replay_data"
    if any(not row.get("same_seed") for row in rows):
        return "blocked_seed_mismatch"
    if runtime_executed:
        return "runtime_replay_executed"
    return "existing_runtime_trace_used"


def _extract_value(text: str, key: str) -> str | None:
    prefix = f"{key}="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return None
