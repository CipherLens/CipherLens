"""Strict target-emitted capture protocol to RuntimeEvent bridge.

The target binary emits the payload.  This module only parses an exact JSON
envelope and delegates fact construction to the frozen RuntimeEvent emitter.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from runtime_event.emitter import emit_runtime_event_v0_1


PREFIX = "CIPHERLENS_CAPTURE_V0_1 "
PROTOCOL_VERSION = "0.1"
_FIELDS = {
    "protocol_version",
    "capture_binding_ref",
    "contract_observable_ref",
    "observation_binding_ref",
    "semantic_role",
    "acquisition_kind",
    "phase",
    "subject_ref",
    "operation_ref",
    "correlation_group_ref",
    "status",
    "value_type",
    "value",
    "sequence_index",
}


def parse_target_capture_line(line: str) -> dict[str, Any]:
    """Parse one exact target-emitted payload without regex or inference."""
    if not line.startswith(PREFIX):
        raise ValueError("not a C1 target capture line")
    payload = json.loads(line[len(PREFIX):])
    if not isinstance(payload, dict) or set(payload) != _FIELDS:
        raise ValueError("target capture payload fields are not closed")
    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported target capture protocol version")
    if type(payload["sequence_index"]) is not int or payload["sequence_index"] < 0:
        raise ValueError("target capture sequence index must be nonnegative")
    return payload


def target_capture_to_runtime_event(
    payload: Mapping[str, Any],
    *,
    execution_attempt_ref: str,
    evidence_ref: str,
) -> dict[str, Any]:
    """Materialize a fact-only RuntimeEvent from an already parsed payload."""
    if set(payload) != _FIELDS or payload.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("validated target capture payload required")
    return emit_runtime_event_v0_1(
        execution_attempt_ref=execution_attempt_ref,
        contract_observable_ref=payload["contract_observable_ref"],
        observation_binding_ref=payload["observation_binding_ref"],
        merge_capture_ref=payload["capture_binding_ref"],
        semantic_role=payload["semantic_role"],
        acquisition_kind=payload["acquisition_kind"],
        phase=payload["phase"],
        subject_ref=payload["subject_ref"],
        operation_ref=payload["operation_ref"],
        correlation_group_ref=payload["correlation_group_ref"],
        status=payload["status"],
        value_type=payload["value_type"],
        value=payload["value"],
        evidence_refs=[evidence_ref],
        producer={
            "emitter_name": "cipherlens-target-capture-bridge",
            "emitter_version": "v0.1",
        },
    )
