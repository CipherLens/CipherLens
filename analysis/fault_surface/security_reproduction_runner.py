"""Read-only same-seed replay comparison for security validation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


REQUIRED_LIBRARIES = ("mbedtls", "wolfssl", "botan")
OUTPUT_FIELDS = (
    "return_code",
    "accepted_or_rejected",
    "verification_result",
    "signature_valid",
    "key_usage_result",
    "lifecycle_state",
    "oracle_classification",
    "classification",
)


class SecurityReproductionRunner:
    """Compare existing runtime traces without mutation or pressure."""

    schema = "security_reproduction_runner_v1"

    def replay(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
    ) -> dict[str, Any]:
        seed_id = str(seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed")
        traces = _collect_traces(seed_context, security_candidate)
        rows = [_matrix_row(library, seed_id, traces) for library in REQUIRED_LIBRARIES]
        stable = all(row["trace_found"] and row["same_seed"] for row in rows)
        diff = _execution_trace_diff(seed_id, rows)
        return {
            "schema": self.schema,
            "mode": "same_seed_replay_read_only",
            "mutation_executed": False,
            "pressure_injection_executed": False,
            "runtime_executed_by_this_layer": False,
            "oracle_reevaluation_mode": "read_only_existing_trace",
            "reproducibility_matrix": {
                "schema": "reproducibility_matrix_v2",
                "seed_id": seed_id,
                "required_libraries": list(REQUIRED_LIBRARIES),
                "reproducibility": "stable" if stable else "blocked_missing_runtime_replay_trace",
                "rows": rows,
                "same_seed_replay": stable,
                "identical_input_required": True,
                "candidate_queue_written": False,
            },
            "execution_trace_diff": diff,
            "candidate_queue_written": False,
        }


def replay(seed_context: Mapping[str, Any], security_candidate: Mapping[str, Any]) -> dict[str, Any]:
    """Run the read-only replay comparison."""

    return SecurityReproductionRunner().replay(seed_context, security_candidate)


def _collect_traces(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    traces: list[Mapping[str, Any]] = []
    for source in (seed_context, security_candidate):
        for key in (
            "runtime_results",
            "runtime_traces",
            "execution_traces",
            "oracle_results",
            "observations",
        ):
            value = source.get(key)
            traces.extend(_as_trace_list(value))
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


def _matrix_row(library: str, seed_id: str, traces: list[Mapping[str, Any]]) -> dict[str, Any]:
    trace = _find_library_trace(library, traces)
    if trace is None:
        return {
            "library": library,
            "trace_found": False,
            "same_seed": False,
            "input_identity_status": "missing_trace",
            "output_signature": {},
            "oracle_classification": "missing_or_not_found",
            "replay_status": "blocked_missing_trace",
        }
    trace_seed = str(trace.get("seed_id") or trace.get("seed_candidate_id") or seed_id)
    output_signature = {field: trace.get(field) for field in OUTPUT_FIELDS if field in trace}
    return {
        "library": library,
        "trace_found": True,
        "same_seed": trace_seed == seed_id,
        "input_identity_status": "same_seed_input" if trace_seed == seed_id else "seed_mismatch",
        "output_signature": output_signature,
        "oracle_classification": trace.get("oracle_classification") or trace.get("classification") or "observation",
        "replay_status": "stable_trace_available" if trace_seed == seed_id else "blocked_seed_mismatch",
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


def _execution_trace_diff(seed_id: str, rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    signatures = {
        str(row["library"]): row.get("output_signature", {})
        for row in rows
        if row.get("trace_found")
    }
    unique = {repr(sorted(sig.items())) for sig in signatures.values()}
    return {
        "schema": "execution_trace_diff_v1",
        "seed_id": seed_id,
        "compared_library_count": len(signatures),
        "output_difference_count": max(0, len(unique) - 1),
        "has_output_difference": len(unique) > 1,
        "differences": signatures,
        "mutation_executed": False,
        "pressure_injection_executed": False,
        "candidate_queue_written": False,
    }
