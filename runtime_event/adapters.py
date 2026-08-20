"""Adapters consume validated RuntimeEvents, never raw process output."""

from __future__ import annotations

from typing import Any, Mapping

from .emitter import emit_runtime_event_v0_1
from .model import SCHEMA


_LEGACY_FIELDS = {
    "contract_observable_ref", "observation_binding_ref", "merge_capture_ref",
    "semantic_role", "acquisition_kind", "phase", "subject_ref",
    "operation_ref", "correlation_group_ref", "status", "value_type", "value",
    "evidence_refs", "producer",
}
_TRACE_FIELDS = (
    "contract_observable_ref", "observation_binding_ref", "merge_capture_ref",
    "semantic_role", "value", "status", "correlation_group_ref", "evidence_refs",
)


def legacy_oracle_to_runtime_event(
    event: Mapping[str, Any], execution_attempt_ref: str
) -> dict[str, Any]:
    """Adapt a parsed legacy event without inventing its future witness."""
    if isinstance(event, str):
        raise TypeError("legacy adapter requires a parsed event object")
    fields = {key: value for key, value in event.items() if key in _LEGACY_FIELDS}
    fields["execution_attempt_ref"] = execution_attempt_ref
    fields.setdefault("evidence_refs", [])
    fields.setdefault(
        "producer", {"emitter_name": "legacy-oracle-adapter", "emitter_version": "v0.1"}
    )
    result = emit_runtime_event_v0_1(**fields)
    witness_ref = event.get("witness_ref")
    if witness_ref and not str(witness_ref).startswith("pending"):
        result["execution_witness_ref"] = witness_ref
    return result


def runtime_event_observation(event: Mapping[str, Any]) -> dict[str, Any]:
    """Map one validated event to typed trace-observation input, not a Trace."""
    if isinstance(event, str) or event.get("schema_version") != SCHEMA:
        raise ValueError("trace adapter requires a RuntimeEvent object")
    return {key: event[key] for key in _TRACE_FIELDS}
