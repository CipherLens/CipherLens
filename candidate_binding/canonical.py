"""Canonical immutable CandidateBinding serialization."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Mapping


_BINDING_LISTS = (
    "subject_bindings", "operation_bindings", "input_bindings", "intervention_bindings",
    "continuity_bindings", "observation_bindings", "correlation_bindings",
)
_ID_KEYS = {
    "subject_bindings": "subject_binding_id", "operation_bindings": "operation_binding_id",
    "input_bindings": "input_binding_id", "intervention_bindings": "intervention_binding_id",
    "continuity_bindings": "continuity_binding_id", "observation_bindings": "observation_binding_id",
    "correlation_bindings": "correlation_binding_id",
}
_SET_LIST_KEYS = {
    "template_object_slot_refs", "verified_fact_refs", "evidence_refs", "argument_binding_refs",
    "participant_binding_refs", "type_constraints", "equivalence_fact_refs", "subject_binding_refs",
    "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs",
    "correlation_group_refs",
}


def normalize_candidate_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for name in _BINDING_LISTS:
        items = normalized.get(name, [])
        for item in items:
            for key, child in list(item.items()):
                if key in _SET_LIST_KEYS and isinstance(child, list):
                    item[key] = sorted(dict.fromkeys(child))
        if name == "operation_bindings":
            normalized[name] = sorted(items, key=lambda x: (x.get("sequence_index", -1), x.get("operation_binding_id", "")))
        else:
            normalized[name] = sorted(items, key=lambda x: x.get(_ID_KEYS[name], ""))
    construction = normalized.get("construction")
    if isinstance(construction, dict):
        for key in ("verified_fact_refs", "evidence_refs"):
            if isinstance(construction.get(key), list):
                construction[key] = sorted(dict.fromkeys(construction[key]))
    return normalized


def candidate_semantic_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = normalize_candidate_binding(value)
    normalized.pop("binding_id", None)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def expected_binding_id(value: Mapping[str, Any]) -> str:
    return "binding:" + hashlib.sha256(candidate_semantic_bytes(value)).hexdigest()


def canonical_candidate_binding_bytes(value: Mapping[str, Any]) -> bytes:
    from candidate_binding.validate import validate_candidate_binding_or_raise

    normalized = normalize_candidate_binding(value)
    validate_candidate_binding_or_raise(normalized)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def candidate_binding_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_candidate_binding_bytes(value)).hexdigest()


def normalize_validation(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    normalized["check_results"] = sorted(normalized.get("check_results", []), key=lambda x: x.get("check_id", ""))
    normalized["reason_codes"] = sorted(dict.fromkeys(normalized.get("reason_codes", [])))
    for check in normalized["check_results"]:
        for key in ("binding_refs", "verified_fact_refs", "evidence_refs", "missing_requirements"):
            check[key] = sorted(dict.fromkeys(check.get(key, [])))
    return normalized


def canonical_validation_bytes(value: Mapping[str, Any]) -> bytes:
    from candidate_binding.validate import validate_validation_artifact_or_raise

    normalized = normalize_validation(value)
    validate_validation_artifact_or_raise(normalized)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def validation_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_validation_bytes(value)).hexdigest()
