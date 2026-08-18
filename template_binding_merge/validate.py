"""Closed recursive runtime validation for all Batch 5B artifacts."""

from __future__ import annotations

from collections import Counter
import re
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from template_binding_merge.model import (
    ADAPTATION_SCHEMA_VERSION,
    BOUND_SOURCE_SCHEMA_VERSION,
    MERGE_SCHEMA_VERSION,
    SOURCE_MAP_SCHEMA_VERSION,
    VALIDATION_SCHEMA_VERSION,
    VALIDATOR_REGISTRY_VERSION,
    AdaptationHoleType,
    CandidateElementKind,
    CheckResult,
    HoleResolver,
    MergeError,
    RegionKind,
    RenderDisposition,
    RestrictedEditType,
    SlotKind,
    StructuralObligationType,
    ValidationRouting,
    ValidationStatus,
    ValidatorType,
)


_SHA = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{1,511}$")
_FORBIDDEN = {
    "rag_similarity_score", "ranking_score", "llm_confidence", "provider_confidence",
    "provider_billing", "token_data", "latency", "final_source_code", "compile_result",
    "compile_command_result", "run_result", "runtime_result", "sanitizer_result",
    "contract_relation_result", "verdict", "vulnerability_confirmation", "cve_status",
    "disclosure_maturity", "satisfied", "violated", "unknown",
}

_MERGE_TOP = {
    "schema_version", "merge_id", "trigger_template_ref", "trigger_template_digest",
    "trigger_template_source_artifact_ref", "trigger_template_source_artifact_digest",
    "trigger_template_interface_ref", "trigger_template_interface_digest",
    "candidate_binding_ref", "candidate_binding_digest", "candidate_binding_validation_ref",
    "candidate_binding_validation_digest", "target_scope", "subject_realizations",
    "slot_bindings", "anchor_bindings", "identity_realizations",
    "observation_capture_bindings", "correlation_realizations", "adaptation_holes",
    "structural_obligations", "construction",
}
_SCOPE = {"library", "version", "surface_ref"}
_SUBJECT = {
    "subject_realization_id", "subject_binding_ref", "identity_group_ref", "storage_ref",
    "target_subject_ref", "target_type_ref", "ownership", "lifetime_region",
    "operation_binding_refs", "observation_binding_refs", "verified_fact_refs", "evidence_refs",
}
_SLOT_BINDING = {
    "mapping_id", "template_slot_ref", "slot_kind", "candidate_element_kind",
    "candidate_element_ref", "target_semantic_ref", "occurrence_index",
    "render_disposition", "adaptation_hole_refs", "verified_fact_refs", "evidence_refs",
}
_ANCHOR = {
    "anchor_binding_id", "template_slot_ref", "slot_kind", "candidate_binding_refs",
    "ordered_candidate_refs", "identity_group_refs", "merge_mapping_refs",
    "verified_fact_refs", "evidence_refs",
}
_IDENTITY = {
    "identity_realization_id", "identity_group_ref", "storage_ref", "subject_binding_refs",
    "operation_binding_refs", "observation_binding_refs", "lifetime_region", "ownership",
    "evidence_refs",
}
_CAPTURE = {
    "capture_binding_id", "observation_binding_ref", "contract_observable_ref",
    "template_observation_slot_ref", "target_subject_binding_ref",
    "target_operation_binding_ref", "semantic_source_ref", "acquisition_kind", "phase",
    "value_type", "capture_code_ref", "adaptation_hole_ref", "correlation_refs",
    "participant_refs", "execution_trace_field_ref",
}
_CORRELATION = {
    "correlation_realization_id", "correlation_binding_ref", "correlation_kind",
    "subject_binding_refs", "operation_binding_refs", "intervention_binding_refs",
    "observation_binding_refs", "participant_refs", "execution_trace_group_ref",
    "verified_fact_refs", "evidence_refs",
}
_HOLE = {
    "hole_id", "hole_type", "required", "resolver", "syntax_kind", "allowed_edit_types",
    "allowed_replacement_digests", "semantic_guard_refs", "target_region_ref", "dependencies",
    "type_constraints",
}
_OBLIGATION = {
    "obligation_id", "obligation_type", "required", "typed_refs", "ordered_refs",
    "identity_group_refs", "template_anchor_refs", "candidate_binding_refs",
    "advisory_description",
}
_CONSTRUCTION = {
    "producer", "registry_versions", "verified_fact_refs", "evidence_refs",
    "canonical_upstream_refs",
}
_BOUND_SOURCE_TOP = {
    "schema_version", "bound_source_id", "merge_ref", "merge_digest", "source_artifact_ref",
    "source_digest", "source_map_ref", "source_map_digest", "renderer_id", "renderer_version",
    "language", "unresolved_hole_refs", "build_spec_ref", "build_spec_digest",
}
_SOURCE_MAP_TOP = {
    "schema_version", "source_map_id", "merge_ref", "merge_digest",
    "base_template_source_ref", "base_template_source_digest", "regions",
    "ordered_operation_records", "observation_capture_records", "identity_storage_records",
}
_REGION = {
    "region_id", "region_kind", "source_range", "protected", "canonical_digest",
    "template_slot_refs", "merge_mapping_refs", "adaptation_hole_refs",
    "observation_capture_refs",
}
_RANGE = {"byte_start", "byte_end"}
_OP_RECORD = {
    "record_id", "operation_binding_ref", "template_slot_ref", "merge_mapping_ref",
    "target_symbol_ref", "sequence_index", "region_ref",
}
_OBS_RECORD = {
    "record_id", "observation_binding_ref", "capture_binding_ref", "semantic_source_ref",
    "acquisition_kind", "phase", "region_ref",
}
_IDENTITY_RECORD = {
    "record_id", "identity_group_ref", "storage_ref", "subject_binding_refs", "region_ref",
}
_PROPOSAL_TOP = {
    "schema_version", "proposal_id", "merge_ref", "merge_digest", "base_bound_source_ref",
    "base_bound_source_digest", "provider_provenance", "epistemic_status", "restricted_edits",
}
_PROVIDER = {"provider_id", "provider_version", "request_digest"}
_EDIT = {
    "edit_id", "edit_type", "hole_ref", "base_source_digest", "expected_syntax_kind",
    "replacement",
}
_VALIDATION_TOP = {
    "schema_version", "validation_id", "merge_ref", "merge_digest", "bound_source_ref",
    "bound_source_digest", "validator_registry_version", "status", "routing",
    "check_results", "reason_codes",
}
_CHECK = {
    "check_id", "validator_type", "result", "merge_refs", "evidence_refs", "reason_code",
    "missing_requirements",
}

_OWNERSHIP = {"CALLER_OWNED", "LIBRARY_OWNED", "BORROWED"}
_ACQUISITIONS = {
    "RETURN_VALUE", "OUT_PARAMETER", "BOUND_VALUE", "POINTER_DELTA", "BUFFER_SNAPSHOT",
    "OBJECT_ACCESSOR", "STATE_PROBE", "PROCESS_EVENT", "TIMING_SOURCE",
}
_PHASES = {"BEFORE_STEP", "DURING_STEP", "AFTER_STEP", "BETWEEN_STEPS", "FOLLOWUP", "PROCESS_END"}


def validate_merge(value: Any) -> list[str]:
    from template_binding_merge.canonical import expected_merge_id

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _MERGE_TOP, errors)
    _forbidden_recursive(value, "$", errors)
    _constant(value.get("schema_version"), MERGE_SCHEMA_VERSION, "schema_version", errors)
    for key in (
        "merge_id", "trigger_template_ref", "trigger_template_interface_ref", "candidate_binding_ref",
        "candidate_binding_validation_ref",
    ):
        _ref(value.get(key), key, errors)
    for key in (
        "trigger_template_digest", "trigger_template_source_artifact_digest",
        "trigger_template_interface_digest", "candidate_binding_digest",
        "candidate_binding_validation_digest",
    ):
        _sha(value.get(key), key, errors)
    _repo_path(value.get("trigger_template_source_artifact_ref"), "trigger_template_source_artifact_ref", errors)
    scope = _object(value.get("target_scope"), "target_scope", _SCOPE, errors)
    if scope:
        for key in _SCOPE:
            _text(scope.get(key), f"target_scope.{key}", errors)
        if isinstance(scope.get("library"), str) and scope["library"] != scope["library"].lower():
            errors.append("target_scope.library: must be lowercase")

    subjects = _records(value.get("subject_realizations"), "subject_realizations", _SUBJECT, "subject_realization_id", 1, errors)
    for index, item in enumerate(subjects):
        path = f"subject_realizations[{index}]"
        for key in ("subject_realization_id", "subject_binding_ref", "identity_group_ref", "storage_ref", "target_subject_ref", "target_type_ref", "lifetime_region"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("ownership"), f"{path}.ownership", _OWNERSHIP, errors)
        _ref_lists(item, path, ("operation_binding_refs", "observation_binding_refs", "verified_fact_refs", "evidence_refs"), errors)

    mappings = _records(value.get("slot_bindings"), "slot_bindings", _SLOT_BINDING, "mapping_id", 1, errors)
    occurrence_pairs: list[str] = []
    for index, item in enumerate(mappings):
        path = f"slot_bindings[{index}]"
        for key in ("mapping_id", "template_slot_ref", "candidate_element_ref", "target_semantic_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("slot_kind"), f"{path}.slot_kind", _values(SlotKind), errors)
        _enum(item.get("candidate_element_kind"), f"{path}.candidate_element_kind", _values(CandidateElementKind), errors)
        _enum(item.get("render_disposition"), f"{path}.render_disposition", _values(RenderDisposition), errors)
        _nonnegative(item.get("occurrence_index"), f"{path}.occurrence_index", errors)
        _ref_lists(item, path, ("adaptation_hole_refs", "verified_fact_refs", "evidence_refs"), errors)
        occurrence_pairs.append(f"{item.get('template_slot_ref')}\0{item.get('occurrence_index')}")
    _duplicates(occurrence_pairs, "slot_bindings", "slot occurrence", errors)
    occurrences_by_slot: dict[str, list[int]] = {}
    for item in mappings:
        if isinstance(item.get("template_slot_ref"), str) and isinstance(item.get("occurrence_index"), int):
            occurrences_by_slot.setdefault(item["template_slot_ref"], []).append(item["occurrence_index"])
    for slot_ref, occurrences in occurrences_by_slot.items():
        if sorted(occurrences) != list(range(len(occurrences))):
            errors.append(f"slot_bindings: non-contiguous occurrence indexes for {slot_ref!r}")

    anchors = _records(value.get("anchor_bindings"), "anchor_bindings", _ANCHOR, "anchor_binding_id", 0, errors)
    for index, item in enumerate(anchors):
        path = f"anchor_bindings[{index}]"
        for key in ("anchor_binding_id", "template_slot_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("slot_kind"), f"{path}.slot_kind", {"ORDER_ANCHOR", "STATE_ANCHOR"}, errors)
        _ref_lists(item, path, ("candidate_binding_refs", "ordered_candidate_refs", "identity_group_refs", "merge_mapping_refs", "verified_fact_refs", "evidence_refs"), errors)

    identities = _records(value.get("identity_realizations"), "identity_realizations", _IDENTITY, "identity_realization_id", 1, errors)
    for index, item in enumerate(identities):
        path = f"identity_realizations[{index}]"
        for key in ("identity_realization_id", "identity_group_ref", "storage_ref", "lifetime_region"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("ownership"), f"{path}.ownership", _OWNERSHIP, errors)
        _ref_lists(item, path, ("subject_binding_refs", "operation_binding_refs", "observation_binding_refs", "evidence_refs"), errors)

    captures = _records(value.get("observation_capture_bindings"), "observation_capture_bindings", _CAPTURE, "capture_binding_id", 1, errors)
    for index, item in enumerate(captures):
        path = f"observation_capture_bindings[{index}]"
        for key in (
            "capture_binding_id", "observation_binding_ref", "contract_observable_ref",
            "template_observation_slot_ref", "target_subject_binding_ref", "target_operation_binding_ref",
            "semantic_source_ref", "value_type", "execution_trace_field_ref",
        ):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("acquisition_kind"), f"{path}.acquisition_kind", _ACQUISITIONS, errors)
        _enum(item.get("phase"), f"{path}.phase", _PHASES, errors)
        for key in ("capture_code_ref", "adaptation_hole_ref"):
            if item.get(key) is not None:
                _ref(item.get(key), f"{path}.{key}", errors)
        if (item.get("capture_code_ref") is None) == (item.get("adaptation_hole_ref") is None):
            errors.append(f"{path}: exactly one capture_code_ref or adaptation_hole_ref is required")
        _ref_lists(item, path, ("correlation_refs", "participant_refs"), errors)

    correlations = _records(value.get("correlation_realizations"), "correlation_realizations", _CORRELATION, "correlation_realization_id", 0, errors)
    for index, item in enumerate(correlations):
        path = f"correlation_realizations[{index}]"
        for key in ("correlation_realization_id", "correlation_binding_ref", "correlation_kind", "execution_trace_group_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _ref_lists(item, path, ("subject_binding_refs", "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs", "participant_refs", "verified_fact_refs", "evidence_refs"), errors)

    holes = _records(value.get("adaptation_holes"), "adaptation_holes", _HOLE, "hole_id", 0, errors)
    hole_refs = {item.get("hole_id") for item in holes}
    _duplicates(
        [item.get("target_region_ref") for item in holes if isinstance(item.get("target_region_ref"), str)],
        "adaptation_holes", "target_region_ref", errors,
    )
    for index, item in enumerate(holes):
        _validate_hole(item, f"adaptation_holes[{index}]", errors)
        if item.get("hole_id") in item.get("dependencies", []):
            errors.append(f"adaptation_holes[{index}].dependencies: self dependency")
        for dependency in item.get("dependencies", []):
            if dependency not in hole_refs:
                errors.append(f"adaptation_holes[{index}].dependencies: dangling hole {dependency!r}")
    dependency_graph = {
        str(item.get("hole_id")): [str(x) for x in item.get("dependencies", [])]
        for item in holes if isinstance(item.get("hole_id"), str)
    }
    if _has_cycle(dependency_graph):
        errors.append("adaptation_holes.dependencies: dependency cycle")
    for index, mapping in enumerate(mappings):
        for ref in mapping.get("adaptation_hole_refs", []):
            if ref not in hole_refs:
                errors.append(f"slot_bindings[{index}].adaptation_hole_refs: dangling hole {ref!r}")
    for index, capture in enumerate(captures):
        ref = capture.get("adaptation_hole_ref")
        if ref is not None and ref not in hole_refs:
            errors.append(f"observation_capture_bindings[{index}].adaptation_hole_ref: dangling hole")

    obligations = _records(value.get("structural_obligations"), "structural_obligations", _OBLIGATION, "obligation_id", len(StructuralObligationType), errors)
    obligation_types: list[str] = []
    for index, item in enumerate(obligations):
        path = f"structural_obligations[{index}]"
        _ref(item.get("obligation_id"), f"{path}.obligation_id", errors)
        _enum(item.get("obligation_type"), f"{path}.obligation_type", _values(StructuralObligationType), errors)
        _boolean(item.get("required"), f"{path}.required", errors)
        _ref_lists(item, path, ("typed_refs", "ordered_refs", "identity_group_refs", "template_anchor_refs", "candidate_binding_refs"), errors)
        _text(item.get("advisory_description"), f"{path}.advisory_description", errors)
        if isinstance(item.get("obligation_type"), str):
            obligation_types.append(item["obligation_type"])
    if set(obligation_types) != _values(StructuralObligationType):
        errors.append("structural_obligations: must contain every frozen obligation type exactly once")
    _duplicates(obligation_types, "structural_obligations", "obligation_type", errors)

    construction = _object(value.get("construction"), "construction", _CONSTRUCTION, errors)
    if construction:
        _ref(construction.get("producer"), "construction.producer", errors)
        _ref_lists(construction, "construction", ("registry_versions", "verified_fact_refs", "evidence_refs", "canonical_upstream_refs"), errors)

    if isinstance(value.get("merge_id"), str) and value.get("merge_id") != expected_merge_id(value):
        errors.append("merge_id: does not match immutable semantic content")
    return _unique(errors)


def validate_merge_or_raise(value: Any) -> None:
    _raise("Template--CandidateBinding Merge", validate_merge(value))


def validate_bound_source(value: Any) -> list[str]:
    from template_binding_merge.canonical import expected_bound_source_id

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _BOUND_SOURCE_TOP, errors)
    _forbidden_recursive(value, "$", errors)
    _constant(value.get("schema_version"), BOUND_SOURCE_SCHEMA_VERSION, "schema_version", errors)
    for key in ("bound_source_id", "merge_ref", "source_map_ref", "renderer_id", "renderer_version", "build_spec_ref"):
        _ref(value.get(key), key, errors)
    _text(value.get("language"), "language", errors)
    for key in ("merge_digest", "source_digest", "source_map_digest", "build_spec_digest"):
        _sha(value.get(key), key, errors)
    _repo_path(value.get("source_artifact_ref"), "source_artifact_ref", errors)
    _ref_list(value.get("unresolved_hole_refs"), "unresolved_hole_refs", 0, errors)
    if isinstance(value.get("bound_source_id"), str) and value.get("bound_source_id") != expected_bound_source_id(value):
        errors.append("bound_source_id: does not match immutable envelope content")
    return _unique(errors)


def validate_bound_source_or_raise(value: Any) -> None:
    _raise("Bound Source", validate_bound_source(value))


def validate_source_map(value: Any) -> list[str]:
    from template_binding_merge.canonical import expected_source_map_id

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _SOURCE_MAP_TOP, errors)
    _forbidden_recursive(value, "$", errors)
    _constant(value.get("schema_version"), SOURCE_MAP_SCHEMA_VERSION, "schema_version", errors)
    for key in ("source_map_id", "merge_ref"):
        _ref(value.get(key), key, errors)
    for key in ("merge_digest", "base_template_source_digest"):
        _sha(value.get(key), key, errors)
    _repo_path(value.get("base_template_source_ref"), "base_template_source_ref", errors)

    regions = _records(value.get("regions"), "regions", _REGION, "region_id", 1, errors)
    region_refs = {item.get("region_id") for item in regions}
    previous_end = -1
    for index, item in enumerate(regions):
        path = f"regions[{index}]"
        _ref(item.get("region_id"), f"{path}.region_id", errors)
        _enum(item.get("region_kind"), f"{path}.region_kind", _values(RegionKind), errors)
        _boolean(item.get("protected"), f"{path}.protected", errors)
        _sha(item.get("canonical_digest"), f"{path}.canonical_digest", errors)
        source_range = _object(item.get("source_range"), f"{path}.source_range", _RANGE, errors)
        if source_range:
            start = source_range.get("byte_start")
            end = source_range.get("byte_end")
            _nonnegative(start, f"{path}.source_range.byte_start", errors)
            _nonnegative(end, f"{path}.source_range.byte_end", errors)
            if isinstance(start, int) and isinstance(end, int):
                if start > end:
                    errors.append(f"{path}.source_range: byte_start exceeds byte_end")
                if start == end:
                    errors.append(f"{path}.source_range: empty regions are forbidden")
                if start < previous_end:
                    errors.append(f"{path}.source_range: regions overlap or are out of order")
                previous_end = end
        _ref_lists(item, path, ("template_slot_refs", "merge_mapping_refs", "adaptation_hole_refs", "observation_capture_refs"), errors)
        if item.get("region_kind") == RegionKind.ADAPTATION_HOLE.value and item.get("protected") is not False:
            errors.append(f"{path}: adaptation-hole region must be unprotected")
        if item.get("region_kind") != RegionKind.ADAPTATION_HOLE.value and item.get("protected") is not True:
            errors.append(f"{path}: structural region must be protected")

    op_records = _records(value.get("ordered_operation_records"), "ordered_operation_records", _OP_RECORD, "record_id", 0, errors)
    sequence_indexes: list[int] = []
    for index, item in enumerate(op_records):
        path = f"ordered_operation_records[{index}]"
        for key in ("record_id", "operation_binding_ref", "template_slot_ref", "merge_mapping_ref", "target_symbol_ref", "region_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _nonnegative(item.get("sequence_index"), f"{path}.sequence_index", errors)
        if item.get("region_ref") not in region_refs:
            errors.append(f"{path}.region_ref: dangling region")
        if isinstance(item.get("sequence_index"), int):
            sequence_indexes.append(item["sequence_index"])
    if sequence_indexes != sorted(sequence_indexes):
        errors.append("ordered_operation_records: sequence_index order is not canonical")

    obs_records = _records(value.get("observation_capture_records"), "observation_capture_records", _OBS_RECORD, "record_id", 0, errors)
    for index, item in enumerate(obs_records):
        path = f"observation_capture_records[{index}]"
        for key in ("record_id", "observation_binding_ref", "capture_binding_ref", "semantic_source_ref", "acquisition_kind", "phase", "region_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        if item.get("region_ref") not in region_refs:
            errors.append(f"{path}.region_ref: dangling region")

    identity_records = _records(value.get("identity_storage_records"), "identity_storage_records", _IDENTITY_RECORD, "record_id", 0, errors)
    for index, item in enumerate(identity_records):
        path = f"identity_storage_records[{index}]"
        for key in ("record_id", "identity_group_ref", "storage_ref", "region_ref"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _ref_list(item.get("subject_binding_refs"), f"{path}.subject_binding_refs", 1, errors)
        if item.get("region_ref") not in region_refs:
            errors.append(f"{path}.region_ref: dangling region")
    if isinstance(value.get("source_map_id"), str) and value.get("source_map_id") != expected_source_map_id(value):
        errors.append("source_map_id: does not match immutable content")
    return _unique(errors)


def validate_source_map_or_raise(value: Any) -> None:
    _raise("SourceMap", validate_source_map(value))


def validate_adaptation_proposal(value: Any) -> list[str]:
    from template_binding_merge.canonical import expected_adaptation_proposal_id

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _PROPOSAL_TOP, errors)
    _forbidden_recursive(value, "$", errors)
    _constant(value.get("schema_version"), ADAPTATION_SCHEMA_VERSION, "schema_version", errors)
    for key in ("proposal_id", "merge_ref", "base_bound_source_ref"):
        _ref(value.get(key), key, errors)
    for key in ("merge_digest", "base_bound_source_digest"):
        _sha(value.get(key), key, errors)
    _constant(value.get("epistemic_status"), "PROPOSED", "epistemic_status", errors)
    provider = _object(value.get("provider_provenance"), "provider_provenance", _PROVIDER, errors)
    if provider:
        _ref(provider.get("provider_id"), "provider_provenance.provider_id", errors)
        _ref(provider.get("provider_version"), "provider_provenance.provider_version", errors)
        _sha(provider.get("request_digest"), "provider_provenance.request_digest", errors)
    edits = _records(value.get("restricted_edits"), "restricted_edits", _EDIT, "edit_id", 1, errors)
    for index, item in enumerate(edits):
        path = f"restricted_edits[{index}]"
        for key in ("edit_id", "hole_ref", "expected_syntax_kind"):
            _ref(item.get(key), f"{path}.{key}", errors)
        _enum(item.get("edit_type"), f"{path}.edit_type", _values(RestrictedEditType), errors)
        _sha(item.get("base_source_digest"), f"{path}.base_source_digest", errors)
        _text(item.get("replacement"), f"{path}.replacement", errors)
    if isinstance(value.get("proposal_id"), str) and value.get("proposal_id") != expected_adaptation_proposal_id(value):
        errors.append("proposal_id: does not match immutable proposed content")
    return _unique(errors)


def validate_adaptation_proposal_or_raise(value: Any) -> None:
    _raise("AdaptationProposal", validate_adaptation_proposal(value))


def validate_merge_validation(value: Any) -> list[str]:
    from template_binding_merge.canonical import expected_merge_validation_id

    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _VALIDATION_TOP, errors)
    _forbidden_recursive(value, "$", errors)
    _constant(value.get("schema_version"), VALIDATION_SCHEMA_VERSION, "schema_version", errors)
    _constant(value.get("validator_registry_version"), VALIDATOR_REGISTRY_VERSION, "validator_registry_version", errors)
    for key in ("validation_id", "merge_ref", "bound_source_ref"):
        _ref(value.get(key), key, errors)
    for key in ("merge_digest", "bound_source_digest"):
        _sha(value.get(key), key, errors)
    _enum(value.get("status"), "status", _values(ValidationStatus), errors)
    _enum(value.get("routing"), "routing", _values(ValidationRouting), errors)
    checks = _records(value.get("check_results"), "check_results", _CHECK, "check_id", len(ValidatorType), errors)
    types: list[str] = []
    for index, item in enumerate(checks):
        path = f"check_results[{index}]"
        _ref(item.get("check_id"), f"{path}.check_id", errors)
        _enum(item.get("validator_type"), f"{path}.validator_type", _values(ValidatorType), errors)
        _enum(item.get("result"), f"{path}.result", _values(CheckResult), errors)
        _ref_lists(item, path, ("merge_refs", "evidence_refs", "missing_requirements"), errors)
        _ref(item.get("reason_code"), f"{path}.reason_code", errors)
        if isinstance(item.get("validator_type"), str):
            types.append(item["validator_type"])
    if set(types) != _values(ValidatorType):
        errors.append("check_results: must contain each frozen validator exactly once")
    _duplicates(types, "check_results", "validator_type", errors)
    _ref_list(value.get("reason_codes"), "reason_codes", 0, errors)
    if isinstance(value.get("validation_id"), str) and value.get("validation_id") != expected_merge_validation_id(value):
        errors.append("validation_id: does not match immutable validation content")
    return _unique(errors)


def validate_merge_validation_or_raise(value: Any) -> None:
    _raise("MergeValidation", validate_merge_validation(value))


def _validate_hole(item: Mapping[str, Any], path: str, errors: list[str]) -> None:
    for key in ("hole_id", "syntax_kind", "target_region_ref"):
        _ref(item.get(key), f"{path}.{key}", errors)
    _enum(item.get("hole_type"), f"{path}.hole_type", _values(AdaptationHoleType), errors)
    _boolean(item.get("required"), f"{path}.required", errors)
    _enum(item.get("resolver"), f"{path}.resolver", _values(HoleResolver), errors)
    _enum_list(item.get("allowed_edit_types"), f"{path}.allowed_edit_types", _values(RestrictedEditType), 1, errors)
    _sha_list(item.get("allowed_replacement_digests"), f"{path}.allowed_replacement_digests", 1, errors)
    _ref_lists(item, path, ("semantic_guard_refs", "dependencies"), errors)
    _text_list(item.get("type_constraints"), f"{path}.type_constraints", 0, errors)


def _records(value: Any, path: str, keys: set[str], id_key: str, minimum: int, errors: list[str]) -> list[Mapping[str, Any]]:
    items = _list(value, path, minimum, errors)
    result: list[Mapping[str, Any]] = []
    ids: list[str] = []
    for index, item in enumerate(items):
        record = _object(item, f"{path}[{index}]", keys, errors)
        if record is not None:
            result.append(record)
            if isinstance(record.get(id_key), str):
                ids.append(record[id_key])
    _duplicates(ids, path, id_key, errors)
    return result


def _keys(value: Mapping[str, Any], path: str, expected: set[str], errors: list[str]) -> None:
    for key in sorted(expected - set(value)):
        errors.append(f"{path}.{key}: required field missing")
    for key in sorted(set(value) - expected, key=str):
        errors.append(f"{path}.{key}: unknown field")


def _object(value: Any, path: str, keys: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, keys, errors)
    return value


def _list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _ref_list(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    refs = []
    for index, item in enumerate(items):
        _ref(item, f"{path}[{index}]", errors)
        if isinstance(item, str):
            refs.append(item)
    _duplicates(refs, path, "reference", errors)
    return refs


def _text_list(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    texts = []
    for index, item in enumerate(items):
        _text(item, f"{path}[{index}]", errors)
        if isinstance(item, str):
            texts.append(item)
    _duplicates(texts, path, "value", errors)
    return texts


def _ref_lists(item: Mapping[str, Any], path: str, keys: tuple[str, ...], errors: list[str]) -> None:
    for key in keys:
        _ref_list(item.get(key), f"{path}.{key}", 0, errors)


def _sha_list(value: Any, path: str, minimum: int, errors: list[str]) -> None:
    items = _list(value, path, minimum, errors)
    values = []
    for index, item in enumerate(items):
        _sha(item, f"{path}[{index}]", errors)
        if isinstance(item, str):
            values.append(item)
    _duplicates(values, path, "digest", errors)


def _enum_list(value: Any, path: str, allowed: set[str], minimum: int, errors: list[str]) -> None:
    items = _list(value, path, minimum, errors)
    values = []
    for index, item in enumerate(items):
        _enum(item, f"{path}[{index}]", allowed, errors)
        if isinstance(item, str):
            values.append(item)
    _duplicates(values, path, "value", errors)


def _ref(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        errors.append(f"{path}: invalid reference")


def _text(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _sha(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        errors.append(f"{path}: expected lowercase SHA-256")


def _repo_path(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected repo-relative artifact path")
        return
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or str(pure) != value:
        errors.append(f"{path}: expected normalized repo-relative artifact path")


def _enum(value: Any, path: str, allowed: set[str], errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{path}: unknown value {value!r}")


def _constant(value: Any, expected: str, path: str, errors: list[str]) -> None:
    if value != expected:
        errors.append(f"{path}: expected {expected!r}")


def _boolean(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, bool):
        errors.append(f"{path}: expected boolean")


def _nonnegative(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        errors.append(f"{path}: expected non-negative integer")


def _duplicates(values: list[Any], path: str, label: str, errors: list[str]) -> None:
    for value, count in Counter(values).items():
        if count > 1:
            errors.append(f"{path}: duplicate {label} {value!r}")


def _forbidden_recursive(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in _FORBIDDEN:
                errors.append(f"{path}.{key}: forbidden field")
            _forbidden_recursive(child, f"{path}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbidden_recursive(child, f"{path}[{index}]", errors)


def _values(enum_type: Any) -> set[str]:
    return {item.value for item in enum_type}


def _has_cycle(graph: Mapping[str, list[str]]) -> bool:
    active: set[str] = set()
    complete: set[str] = set()

    def visit(node: str) -> bool:
        if node in active:
            return True
        if node in complete:
            return False
        active.add(node)
        if any(child in graph and visit(child) for child in graph.get(node, [])):
            return True
        active.remove(node)
        complete.add(node)
        return False

    return any(visit(node) for node in graph)


def _unique(errors: list[str]) -> list[str]:
    return sorted(dict.fromkeys(errors))


def _raise(kind: str, errors: list[str]) -> None:
    if errors:
        raise MergeError(kind, errors)
