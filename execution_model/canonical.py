"""Canonical serialization and digest-addressed identity."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from copy import deepcopy
from typing import Any, Mapping


SET_LIST_KEYS = frozenset({
    "reason_codes", "missing_requirements", "invalid_requirements",
    "correlation_refs", "participant_refs", "evidence_refs", "raw_artifact_refs",
    "required_capture_refs", "required_channels", "expected_markers",
    "supporting_broken_relation_refs", "non_evaluable_relation_refs",
})
ID_FIELDS = {
    "cipherlens.execution_handoff.v0.1": "handoff_id",
    "cipherlens.build_spec.v0.1": "build_spec_id",
    "cipherlens.build_record.v0.1": "build_record_id",
    "cipherlens.run_spec.v0.1": "run_spec_id",
    "cipherlens.run_record.v0.1": "run_record_id",
    "cipherlens.execution_witness.v0.1": "witness_id",
    "cipherlens.structured_execution_trace.v0.1": "trace_id",
    "cipherlens.contract_evidence_projection.v0.1": "projection_id",
    "cipherlens.relation_instance_evaluation.v0.1": "evaluation_id",
    "cipherlens.execution_verdict.v0.1": "verdict_id",
    "cipherlens.execution_closure.v0.1": "closure_id",
    "cipherlens.violation_evidence_package.v0.1": "package_id",
    "cipherlens.caller_impact_bridge.v0.1": "bridge_id",
}
PREFIXES = {schema: field.removesuffix("_id").replace("_", "-") for schema, field in ID_FIELDS.items()}


def _normalize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key], str(key)) for key in sorted(value, key=str)}
    if isinstance(value, list):
        items = [_normalize(item) for item in value]
        if parent_key in SET_LIST_KEYS:
            return sorted(items, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return items
    if isinstance(value, tuple):
        return _normalize(list(value), parent_key)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden in canonical semantic artifacts")
    return value


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = _normalize(dict(value))
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def semantic_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def artifact_id(value: Mapping[str, Any]) -> str:
    schema = str(value.get("schema_version") or "")
    field = ID_FIELDS.get(schema)
    if field is None:
        raise ValueError(f"unsupported canonical schema: {schema}")
    body = deepcopy(dict(value))
    body.pop(field, None)
    return f"{PREFIXES[schema]}:{semantic_digest(body)}"


def identify(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    field = ID_FIELDS.get(str(result.get("schema_version") or ""))
    if field is None:
        raise ValueError("unsupported canonical schema")
    result[field] = "pending"
    result[field] = artifact_id(result)
    return result


def artifact_digest(value: Mapping[str, Any]) -> str:
    from execution_model.registry import validate_artifact_or_raise

    validate_artifact_or_raise(value)
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def raw_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
