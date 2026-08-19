"""Rich capture events plus a non-authoritative projection for the frozen runner."""

from __future__ import annotations

import json
from enum import Enum
from typing import Any, Mapping

from target_knowledge.canonical import identified, semantic_digest
from .model import ORACLE_EVENT_SCHEMA


class OracleEventStatus(str, Enum):
    PRESENT = "PRESENT"
    OBSERVED_ABSENCE = "OBSERVED_ABSENCE"
    NOT_REACHED = "NOT_REACHED"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    ACQUISITION_FAILED = "ACQUISITION_FAILED"
    INVALID_VALUE = "INVALID_VALUE"


_ROLES = {"operation_outcome", "return_value", "output_length", "consumed_length", "input_length", "object_state", "fatal_event"}
_REQUIRED = {"witness_ref", "contract_observable_ref", "observation_binding_ref", "merge_capture_ref", "semantic_role", "acquisition_kind", "phase", "subject_ref", "operation_ref", "correlation_group_ref", "status", "value_type"}


def make_oracle_event(**fields: Any) -> dict[str, Any]:
    missing = sorted(_REQUIRED - set(fields))
    if missing:
        raise ValueError(f"oracle event missing fields: {', '.join(missing)}")
    if fields["semantic_role"] not in _ROLES:
        raise ValueError("unsupported oracle-event semantic role")
    if fields["status"] not in {item.value for item in OracleEventStatus}:
        raise ValueError("unsupported oracle-event status")
    result = {"schema_version": ORACLE_EVENT_SCHEMA, "event_version": "0.1", **fields}
    # Crash/sanitizer observations are process evidence, never a contract verdict.
    result["verdict_authority"] = "NONE"
    result["event_digest"] = semantic_digest(result)
    return identified(result, "oracle-event", "event_id")


def event_line(event: Mapping[str, Any]) -> str:
    return "ORACLE_EVENT_V0_1 " + json.dumps(event, sort_keys=True, separators=(",", ":"))


def parse_oracle_event(line: str) -> dict[str, Any]:
    if not line.startswith("ORACLE_EVENT_V0_1 "):
        raise ValueError("not a v0.1 oracle event")
    event = json.loads(line[len("ORACLE_EVENT_V0_1 "):])
    if event.get("schema_version") != ORACLE_EVENT_SCHEMA:
        raise ValueError("wrong oracle event schema")
    return make_oracle_event(**{key: value for key, value in event.items() if key not in {"schema_version", "event_version", "event_digest", "event_id", "verdict_authority"}})


def runner_compat_projection(event: Mapping[str, Any]) -> dict[str, Any]:
    """Projection is acquisition metadata only; it cannot turn absence into safety."""
    status = str(event["status"])
    return {
        "capture_binding_ref": event["observation_binding_ref"],
        "status": status,
        "value_presence": status == OracleEventStatus.PRESENT.value,
        "value": event.get("value"),
        "sequence_index": int(event.get("sequence_index", 0)),
        "channel_active": status not in {OracleEventStatus.CHANNEL_UNAVAILABLE.value, OracleEventStatus.ACQUISITION_FAILED.value},
        "phase_reached": status not in {OracleEventStatus.NOT_REACHED.value},
        "value_artifact_ref": event.get("artifact_ref"),
        "value_artifact_digest": event.get("evidence_digest"),
    }


def make_capture_readiness_spec() -> dict[str, Any]:
    """Preparation-only capture requirements; this is not a witness event."""
    return identified({
        "schema_version": "cipherlens.capture_readiness.v0.1",
        "preparation_status": "PREPARED_FOR_7D_B",
        "witness_generation": "NOT_EXECUTED",
        "cases": {
            "0020": {"required_roles": ["operation_outcome", "consumed_length", "input_length"], "correlation_requirement": "shared operation/input correlation group"},
            "0004": {"required_roles": ["operation_outcome", "return_value", "output_length_before", "output_length_after"], "correlation_requirement": "same operation and output identity"},
            "0005": {"required_roles": ["object_state", "state_transition", "fatal_event", "follow_up_behavior"], "correlation_requirement": "same object lifecycle correlation group"},
        },
        "safety_rules": ["MISSING_EVENT_IS_NOT_SAFE", "SANITIZER_CRASH_SIGNAL_IS_NOT_A_VERDICT"],
        "missing_artifacts": [{"expected_future_artifact_type": "real_oracle_event_witness", "preparation_status": "MISSING_ARTIFACT"}],
    }, "capture-readiness", "capture_readiness_id")
