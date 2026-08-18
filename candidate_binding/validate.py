"""Closed runtime schema validation for CandidateBinding documents."""

from __future__ import annotations

from collections import Counter
import re
from pathlib import PurePosixPath
from typing import Any, Mapping

from candidate_binding.canonical import expected_binding_id
from candidate_binding.model import BINDING_SCHEMA_VERSION, VALIDATION_SCHEMA_VERSION, VALIDATOR_REGISTRY_VERSION, CandidateBindingError, CheckResult, ValidationStatus, ValidatorType
from transfer_signature.profile import _SUBJECT_KINDS


_SHA = re.compile(r"^[0-9a-f]{64}$")
_TOP = {"schema_version", "binding_id", "source_contract_ref", "source_contract_digest", "transfer_signature_ref", "transfer_signature_digest", "trigger_template_ref", "trigger_template_digest", "target_profile_ref", "target_profile_digest", "eligibility_evaluation_ref", "eligibility_evaluation_digest", "target_scope", "subject_bindings", "operation_bindings", "input_bindings", "intervention_bindings", "continuity_bindings", "observation_bindings", "correlation_bindings", "construction"}
_SCOPE = {"library", "version", "surface_ref"}
_SUBJECT = {"subject_binding_id", "contract_object_ref", "template_object_slot_refs", "target_subject_ref", "subject_kind", "semantic_role", "target_type_ref", "identity_group_ref", "ownership", "lifetime", "verified_fact_refs", "evidence_refs"}
_OPERATION = {"operation_binding_id", "binding_kind", "contract_step_ref", "template_call_slot_ref", "operation_role", "target_operation_kind", "target_symbol_ref", "receiver_subject_binding_ref", "argument_binding_refs", "participant_binding_refs", "sequence_index", "verified_fact_refs", "evidence_refs"}
_INPUT = {"input_binding_id", "source_input_ref", "template_input_slot_ref", "target_operation_binding_ref", "target_parameter_ref", "input_role", "value_type", "representation_kind", "encoding", "construction_strategy_ref", "artifact_ref", "type_constraints", "size_range", "ownership", "verified_fact_refs", "evidence_refs"}
_INTERVENTION = {"intervention_binding_id", "contract_intervention_ref", "template_intervention_ref", "target_subject_binding_ref", "target_operation_binding_ref", "target_parameter_ref", "target_state_ref", "intervention_kind", "application_phase", "equivalence_fact_refs", "evidence_refs"}
_CONTINUITY = {"continuity_binding_id", "continuity_kind", "subject_binding_refs", "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs", "verified_fact_refs", "evidence_refs"}
_OBSERVATION = {"observation_binding_id", "contract_observable_ref", "template_observation_ref", "target_subject_binding_ref", "target_operation_binding_ref", "observable_role", "value_type", "acquisition_kind", "phase", "semantic_source_ref", "correlation_group_refs", "participant_binding_refs", "verified_fact_refs", "evidence_refs"}
_CORRELATION = {"correlation_binding_id", "correlation_kind", "subject_binding_refs", "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs", "participant_binding_refs", "verified_fact_refs", "evidence_refs"}
_CONSTRUCTION = {"producer", "version", "verified_fact_refs", "evidence_refs"}
_FORBIDDEN = {"rag_similarity_score", "ranking_score", "llm_confidence", "provider_confidence", "llm_rationale", "provider_billing", "token_data", "eligibility_result", "final_source_code", "compile_result", "run_result", "sanitizer_result", "contract_relation_result", "verdict", "vulnerability_confirmation", "cve_status", "disclosure_maturity", "caller_impact_result", "binding_proposal_ref"}
_OWNERSHIP = {"CALLER_OWNED", "LIBRARY_OWNED", "BORROWED"}
_BINDING_KINDS = {"PRIMARY_CONTRACT_STEP", "SUPPORTING_SETUP", "SUPPORTING_OBSERVATION", "FOLLOWUP", "SUPPORTING_CLEANUP"}
_PHASES = {"BEFORE_OPERATION", "AT_OPERATION", "BETWEEN_OPERATIONS", "FOLLOWUP_SEQUENCE"}
_CONTINUITIES = {"SAME_IDENTITY_ACROSS_OPERATIONS", "SURVIVES_FAILED_OPERATION", "FOLLOWUP_ON_SAME_IDENTITY", "BEFORE_AFTER_SAME_IDENTITY", "REUSE_AFTER_INTERVENTION"}
_ACQUISITIONS = {"RETURN_VALUE", "OUT_PARAMETER", "BOUND_VALUE", "POINTER_DELTA", "BUFFER_SNAPSHOT", "OBJECT_ACCESSOR", "STATE_PROBE", "PROCESS_EVENT", "TIMING_SOURCE"}
_OBS_PHASES = {"BEFORE_STEP", "DURING_STEP", "AFTER_STEP", "BETWEEN_STEPS", "FOLLOWUP", "PROCESS_END"}
_CORRELATIONS = {"SAME_RUN", "SAME_STEP", "SAME_SUBJECT", "SAME_IDENTITY", "BEFORE_AFTER_PAIR", "MULTI_OPERATION_SEQUENCE"}


def validate_candidate_binding(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _TOP, errors)
    _forbidden_recursive(value, "$", errors)
    if value.get("schema_version") != BINDING_SCHEMA_VERSION:
        errors.append(f"schema_version: expected {BINDING_SCHEMA_VERSION!r}")
    _text(value.get("binding_id"), "binding_id", errors)
    for key in ("source_contract_ref", "transfer_signature_ref", "trigger_template_ref", "target_profile_ref", "eligibility_evaluation_ref"):
        _text(value.get(key), key, errors)
    for key in ("source_contract_digest", "transfer_signature_digest", "trigger_template_digest", "target_profile_digest", "eligibility_evaluation_digest"):
        _sha(value.get(key), key, errors)
    scope = _object(value.get("target_scope"), "target_scope", _SCOPE, errors)
    if scope:
        for key in _SCOPE:
            _text(scope.get(key), f"target_scope.{key}", errors)
        if isinstance(scope.get("library"), str) and scope["library"] != scope["library"].lower():
            errors.append("target_scope.library: must be lowercase")

    definitions = (
        ("subject_bindings", _SUBJECT, "subject_binding_id", _validate_subject),
        ("operation_bindings", _OPERATION, "operation_binding_id", _validate_operation),
        ("input_bindings", _INPUT, "input_binding_id", _validate_input),
        ("intervention_bindings", _INTERVENTION, "intervention_binding_id", _validate_intervention),
        ("continuity_bindings", _CONTINUITY, "continuity_binding_id", _validate_continuity),
        ("observation_bindings", _OBSERVATION, "observation_binding_id", _validate_observation),
        ("correlation_bindings", _CORRELATION, "correlation_binding_id", _validate_correlation),
    )
    all_ids: list[str] = []
    for name, keys, id_key, validator in definitions:
        items = _list(value.get(name), name, 0, errors)
        local_ids: list[str] = []
        for index, item in enumerate(items):
            path = f"{name}[{index}]"
            record = _object(item, path, keys, errors)
            if record:
                _text(record.get(id_key), f"{path}.{id_key}", errors)
                validator(record, path, errors)
                if isinstance(record.get(id_key), str):
                    local_ids.append(record[id_key])
                    all_ids.append(record[id_key])
        _duplicates(local_ids, name, id_key, errors)
    _duplicates(all_ids, "$", "binding ID", errors)
    construction = _object(value.get("construction"), "construction", _CONSTRUCTION, errors)
    if construction:
        _text(construction.get("producer"), "construction.producer", errors)
        _text(construction.get("version"), "construction.version", errors)
        _strings(construction.get("verified_fact_refs"), "construction.verified_fact_refs", 0, errors)
        _strings(construction.get("evidence_refs"), "construction.evidence_refs", 0, errors)
    if isinstance(value.get("binding_id"), str) and value.get("binding_id") != expected_binding_id(value):
        errors.append("binding_id: does not match immutable semantic content")
    return sorted(dict.fromkeys(errors))


def validate_candidate_binding_or_raise(value: Any) -> None:
    errors = validate_candidate_binding(value)
    if errors:
        raise CandidateBindingError(errors)


def _validate_subject(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _text(x.get("contract_object_ref"), f"{path}.contract_object_ref", errors)
    _strings(x.get("template_object_slot_refs"), f"{path}.template_object_slot_refs", 0, errors)
    _text(x.get("target_subject_ref"), f"{path}.target_subject_ref", errors)
    _enum(x.get("subject_kind"), f"{path}.subject_kind", set(_SUBJECT_KINDS), errors)
    for key in ("semantic_role", "target_type_ref", "identity_group_ref", "lifetime"):
        _text(x.get(key), f"{path}.{key}", errors)
    _enum(x.get("ownership"), f"{path}.ownership", _OWNERSHIP, errors)
    _fact_evidence(x, path, errors)


def _validate_operation(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _enum(x.get("binding_kind"), f"{path}.binding_kind", _BINDING_KINDS, errors)
    for key in ("contract_step_ref", "template_call_slot_ref", "operation_role", "target_operation_kind", "target_symbol_ref", "receiver_subject_binding_ref"):
        _text(x.get(key), f"{path}.{key}", errors)
    _strings(x.get("argument_binding_refs"), f"{path}.argument_binding_refs", 0, errors)
    _strings(x.get("participant_binding_refs"), f"{path}.participant_binding_refs", 0, errors)
    if not isinstance(x.get("sequence_index"), int) or x["sequence_index"] < 0:
        errors.append(f"{path}.sequence_index: expected non-negative integer")
    _fact_evidence(x, path, errors)


def _validate_input(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    for key in ("source_input_ref", "template_input_slot_ref", "target_operation_binding_ref", "target_parameter_ref", "input_role", "value_type", "representation_kind", "encoding", "construction_strategy_ref", "ownership"):
        _text(x.get(key), f"{path}.{key}", errors)
    _enum(x.get("representation_kind"), f"{path}.representation_kind", {"DIRECT_VALUE", "ARTIFACT_REF", "ENCODED_BYTES"}, errors)
    if x.get("ownership") not in _OWNERSHIP:
        errors.append(f"{path}.ownership: unknown value {x.get('ownership')!r}")
    if x.get("artifact_ref") is not None:
        _repo_path(x.get("artifact_ref"), f"{path}.artifact_ref", errors)
    _strings(x.get("type_constraints"), f"{path}.type_constraints", 0, errors)
    size = _object(x.get("size_range"), f"{path}.size_range", {"minimum", "maximum"}, errors)
    if size:
        for key in ("minimum", "maximum"):
            if size.get(key) is not None and (not isinstance(size[key], int) or size[key] < 0):
                errors.append(f"{path}.size_range.{key}: expected non-negative integer or null")
        if isinstance(size.get("minimum"), int) and isinstance(size.get("maximum"), int) and size["minimum"] > size["maximum"]:
            errors.append(f"{path}.size_range: minimum exceeds maximum")
    _fact_evidence(x, path, errors)


def _validate_intervention(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    for key in ("contract_intervention_ref", "template_intervention_ref", "target_subject_binding_ref", "target_operation_binding_ref", "intervention_kind", "application_phase"):
        _text(x.get(key), f"{path}.{key}", errors)
    for key in ("target_parameter_ref", "target_state_ref"):
        if x.get(key) is not None:
            _text(x.get(key), f"{path}.{key}", errors)
    _enum(x.get("application_phase"), f"{path}.application_phase", _PHASES, errors)
    _strings(x.get("equivalence_fact_refs"), f"{path}.equivalence_fact_refs", 1, errors)
    _strings(x.get("evidence_refs"), f"{path}.evidence_refs", 1, errors)


def _validate_continuity(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _enum(x.get("continuity_kind"), f"{path}.continuity_kind", _CONTINUITIES, errors)
    for key in ("subject_binding_refs", "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs"):
        _strings(x.get(key), f"{path}.{key}", 0, errors)
    _fact_evidence(x, path, errors)


def _validate_observation(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    for key in ("contract_observable_ref", "template_observation_ref", "target_subject_binding_ref", "target_operation_binding_ref", "observable_role", "value_type", "acquisition_kind", "phase", "semantic_source_ref"):
        _text(x.get(key), f"{path}.{key}", errors)
    _enum(x.get("acquisition_kind"), f"{path}.acquisition_kind", _ACQUISITIONS, errors)
    _enum(x.get("phase"), f"{path}.phase", _OBS_PHASES, errors)
    _strings(x.get("correlation_group_refs"), f"{path}.correlation_group_refs", 0, errors)
    _strings(x.get("participant_binding_refs"), f"{path}.participant_binding_refs", 0, errors)
    _fact_evidence(x, path, errors)


def _validate_correlation(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _enum(x.get("correlation_kind"), f"{path}.correlation_kind", _CORRELATIONS, errors)
    for key in ("subject_binding_refs", "operation_binding_refs", "intervention_binding_refs", "observation_binding_refs", "participant_binding_refs"):
        _strings(x.get(key), f"{path}.{key}", 0, errors)
    _fact_evidence(x, path, errors)


def _fact_evidence(x: Mapping[str, Any], path: str, errors: list[str]) -> None:
    _strings(x.get("verified_fact_refs"), f"{path}.verified_fact_refs", 1, errors)
    _strings(x.get("evidence_refs"), f"{path}.evidence_refs", 1, errors)


def validate_validation_artifact(value: Any) -> list[str]:
    errors: list[str] = []
    top = {"schema_version", "validation_id", "candidate_binding_ref", "candidate_binding_digest", "validator_registry_version", "status", "check_results", "reason_codes"}
    check_keys = {"check_id", "validator_type", "result", "binding_refs", "verified_fact_refs", "evidence_refs", "reason_code", "missing_requirements"}
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", top, errors)
    if value.get("schema_version") != VALIDATION_SCHEMA_VERSION:
        errors.append("schema_version: incorrect validation schema")
    if value.get("validator_registry_version") != VALIDATOR_REGISTRY_VERSION:
        errors.append("validator_registry_version: incorrect version")
    _text(value.get("validation_id"), "validation_id", errors)
    _text(value.get("candidate_binding_ref"), "candidate_binding_ref", errors)
    _sha(value.get("candidate_binding_digest"), "candidate_binding_digest", errors)
    _enum(value.get("status"), "status", {x.value for x in ValidationStatus}, errors)
    checks = _list(value.get("check_results"), "check_results", 10, errors)
    types: list[str] = []
    for index, check in enumerate(checks):
        path = f"check_results[{index}]"
        item = _object(check, path, check_keys, errors)
        if item:
            _text(item.get("check_id"), f"{path}.check_id", errors)
            _enum(item.get("validator_type"), f"{path}.validator_type", {x.value for x in ValidatorType}, errors)
            _enum(item.get("result"), f"{path}.result", {x.value for x in CheckResult}, errors)
            for key in ("binding_refs", "verified_fact_refs", "evidence_refs", "missing_requirements"):
                _strings(item.get(key), f"{path}.{key}", 0, errors)
            _text(item.get("reason_code"), f"{path}.reason_code", errors)
            if isinstance(item.get("validator_type"), str):
                types.append(item["validator_type"])
    if set(types) != {x.value for x in ValidatorType}:
        errors.append("check_results: must contain each validator type exactly once")
    _duplicates(types, "check_results", "validator_type", errors)
    _strings(value.get("reason_codes"), "reason_codes", 0, errors)
    return sorted(dict.fromkeys(errors))


def validate_validation_artifact_or_raise(value: Any) -> None:
    errors = validate_validation_artifact(value)
    if errors:
        raise CandidateBindingError(errors)


def _forbidden_recursive(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            if lowered in _FORBIDDEN:
                errors.append(f"{path}.{key}: forbidden CandidateBinding field")
            _forbidden_recursive(child, f"{path}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbidden_recursive(child, f"{path}[{index}]", errors)


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


def _strings(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    for index, item in enumerate(items):
        _text(item, f"{path}[{index}]", errors)
    return [x for x in items if isinstance(x, str)]


def _text(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _enum(value: Any, path: str, allowed: set[str], errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{path}: unknown value {value!r}")


def _sha(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        errors.append(f"{path}: expected lowercase SHA-256")


def _repo_path(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value or PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts:
        errors.append(f"{path}: expected repo-relative path")


def _duplicates(values: list[str], path: str, label: str, errors: list[str]) -> None:
    for value, count in Counter(values).items():
        if count > 1:
            errors.append(f"{path}: duplicate {label} {value!r}")
