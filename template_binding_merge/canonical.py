"""Canonical JSON serialization for Template--CandidateBinding Merge artifacts."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Mapping


_LIST_IDS = {
    "subject_realizations": "subject_realization_id",
    "slot_bindings": "mapping_id",
    "anchor_bindings": "anchor_binding_id",
    "identity_realizations": "identity_realization_id",
    "observation_capture_bindings": "capture_binding_id",
    "correlation_realizations": "correlation_realization_id",
    "adaptation_holes": "hole_id",
    "structural_obligations": "obligation_id",
    "observation_capture_records": "record_id",
    "identity_storage_records": "record_id",
    "restricted_edits": "edit_id",
    "check_results": "check_id",
}
_SET_KEYS = {
    "template_object_slot_refs", "candidate_binding_refs", "identity_group_refs",
    "template_anchor_refs", "adaptation_hole_refs", "verified_fact_refs", "evidence_refs",
    "subject_binding_refs", "observation_binding_refs",
    "intervention_binding_refs", "correlation_refs", "participant_refs", "dependencies",
    "type_constraints", "allowed_edit_types", "allowed_replacement_digests",
    "template_slot_refs", "merge_mapping_refs", "observation_capture_refs",
    "semantic_guard_refs", "unresolved_hole_refs", "canonical_upstream_refs",
    "registry_versions", "reason_codes", "binding_refs", "missing_requirements",
}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _normalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        result = {str(key): _normalize(child) for key, child in value.items()}
        for key, id_key in _LIST_IDS.items():
            if isinstance(result.get(key), list):
                result[key] = sorted(result[key], key=lambda x: str(x.get(id_key, "")))
        for key in _SET_KEYS:
            if isinstance(result.get(key), list):
                result[key] = sorted(dict.fromkeys(result[key]))
        return result
    if isinstance(value, list):
        return [_normalize(child) for child in value]
    return deepcopy(value)


def normalize_merge(value: Mapping[str, Any]) -> dict[str, Any]:
    return _normalize(value)


def expected_merge_id(value: Mapping[str, Any]) -> str:
    semantic = normalize_merge(value)
    semantic.pop("merge_id", None)
    return "merge:" + semantic_digest(semantic)


def canonical_merge_bytes(value: Mapping[str, Any]) -> bytes:
    from template_binding_merge.validate import validate_merge_or_raise

    normalized = normalize_merge(value)
    validate_merge_or_raise(normalized)
    return canonical_json_bytes(normalized)


def merge_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_merge_bytes(value)).hexdigest()


def _canonical_artifact(value: Mapping[str, Any], validator: str) -> bytes:
    from template_binding_merge import validate as validators

    normalized = _normalize(value)
    getattr(validators, validator)(normalized)
    return canonical_json_bytes(normalized)


def canonical_bound_source_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical_artifact(value, "validate_bound_source_or_raise")


def bound_source_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bound_source_bytes(value)).hexdigest()


def expected_bound_source_id(value: Mapping[str, Any]) -> str:
    semantic = _normalize(value)
    semantic.pop("bound_source_id", None)
    return "bound-source:" + semantic_digest(semantic)


def expected_source_map_id(value: Mapping[str, Any]) -> str:
    semantic = _normalize_source_map(value)
    semantic.pop("source_map_id", None)
    return "source-map:" + semantic_digest(semantic)


def canonical_source_map_bytes(value: Mapping[str, Any]) -> bytes:
    from template_binding_merge.validate import validate_source_map_or_raise

    normalized = _normalize_source_map(value)
    validate_source_map_or_raise(normalized)
    return canonical_json_bytes(normalized)


def source_map_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_source_map_bytes(value)).hexdigest()


def _normalize_source_map(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalize(value)
    normalized["regions"] = sorted(
        normalized.get("regions", []),
        key=lambda item: (item.get("source_range", {}).get("byte_start", -1), item.get("region_id", "")),
    )
    normalized["ordered_operation_records"] = sorted(
        normalized.get("ordered_operation_records", []),
        key=lambda item: (item.get("sequence_index", -1), item.get("record_id", "")),
    )
    return normalized


def expected_adaptation_proposal_id(value: Mapping[str, Any]) -> str:
    semantic = _normalize(value)
    semantic.pop("proposal_id", None)
    return "adaptation-proposal:" + semantic_digest(semantic)


def canonical_adaptation_proposal_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical_artifact(value, "validate_adaptation_proposal_or_raise")


def adaptation_proposal_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_adaptation_proposal_bytes(value)).hexdigest()


def canonical_merge_validation_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical_artifact(value, "validate_merge_validation_or_raise")


def merge_validation_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_merge_validation_bytes(value)).hexdigest()


def expected_merge_validation_id(value: Mapping[str, Any]) -> str:
    semantic = _normalize(value)
    semantic.pop("validation_id", None)
    return "merge-validation:" + semantic_digest(semantic)
