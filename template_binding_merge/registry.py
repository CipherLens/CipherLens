"""Frozen 18-check deterministic Merge validation registry."""

from __future__ import annotations

from collections import Counter
import hashlib
from typing import Any, Mapping

from template_binding_merge.adaptation import _resolved_fills, _validate_base_artifacts
from template_binding_merge.canonical import (
    bound_source_digest,
    expected_merge_validation_id,
    merge_digest,
)
from template_binding_merge.merge import construct_merge
from template_binding_merge.model import (
    VALIDATION_SCHEMA_VERSION,
    VALIDATOR_REGISTRY_VERSION,
    CheckResult,
    HoleResolver,
    ValidationContext,
    ValidationRouting,
    ValidationStatus,
    ValidatorType,
)
from template_binding_merge.render import _record_bytes, _short
from template_binding_merge.validate import validate_merge_validation_or_raise


def validate_merged_source(context: ValidationContext) -> dict[str, Any]:
    """Run every frozen validator with INVALID > INCOMPLETE > VALID precedence."""

    expected = construct_merge(context.gate)
    checks: list[dict[str, Any]] = []
    functions = {
        ValidatorType.REFERENCE_INTEGRITY: lambda: _reference_integrity(context),
        ValidatorType.VALID_BINDING_GATE: lambda: _valid_binding_gate(context),
        ValidatorType.TARGET_SCOPE_CONSISTENCY: lambda: _exact(
            context.merge.get("target_scope"), context.gate.candidate_binding.get("target_scope"),
            "TARGET_SCOPE_EXACT", "TARGET_SCOPE_DRIFT",
        ),
        ValidatorType.SLOT_COVERAGE: lambda: _slot_coverage(context),
        ValidatorType.SLOT_MULTIPLICITY: lambda: _slot_multiplicity(context),
        ValidatorType.SUBJECT_PRESERVATION: lambda: _component(
            context.merge, expected, "subject_realizations", "SUBJECTS_PRESERVED", "SUBJECT_DRIFT"
        ),
        ValidatorType.OPERATION_PRESERVATION: lambda: _mapping_kind(
            context, expected, "OPERATION", "OPERATIONS_PRESERVED", "OPERATION_DRIFT"
        ),
        ValidatorType.INPUT_PRESERVATION: lambda: _mapping_kind(
            context, expected, "INPUT", "INPUTS_PRESERVED", "INPUT_DRIFT"
        ),
        ValidatorType.INTERVENTION_PRESERVATION: lambda: _mapping_kind(
            context, expected, "INTERVENTION", "INTERVENTIONS_PRESERVED", "INTERVENTION_DRIFT"
        ),
        ValidatorType.ORDER_PRESERVATION: lambda: _order(context, expected),
        ValidatorType.STATE_CONTINUITY_PRESERVATION: lambda: _component(
            context.merge, expected, "identity_realizations", "IDENTITY_STORAGE_PRESERVED", "IDENTITY_STORAGE_DRIFT"
        ),
        ValidatorType.OBSERVATION_PRESERVATION: lambda: _component(
            context.merge, expected, "observation_capture_bindings", "OBSERVATIONS_PRESERVED", "OBSERVATION_DRIFT"
        ),
        ValidatorType.CORRELATION_PRESERVATION: lambda: _component(
            context.merge, expected, "correlation_realizations", "CORRELATIONS_PRESERVED", "CORRELATION_DRIFT"
        ),
        ValidatorType.STRUCTURAL_OBLIGATION: lambda: _structural(context, expected),
        ValidatorType.ADAPTATION_BOUNDARY: lambda: _adaptation_boundary(context),
        ValidatorType.FORBIDDEN_SEMANTIC_DRIFT: lambda: _forbidden_drift(context, expected),
        ValidatorType.SOURCE_BINDING_CONSISTENCY: lambda: _source_consistency(context),
        ValidatorType.COMPLETENESS: lambda: _completeness(context),
    }
    for validator_type in ValidatorType:
        result, reason, missing = functions[validator_type]()
        checks.append({
            "check_id": "merge-check:" + validator_type.value.lower().replace("_", "-"),
            "validator_type": validator_type.value,
            "result": result.value,
            "merge_refs": [context.merge.get("merge_id", "merge:invalid")],
            "evidence_refs": [context.bound_source.get("bound_source_id", "bound-source:invalid")],
            "reason_code": reason,
            "missing_requirements": sorted(missing),
        })

    results = [item["result"] for item in checks]
    if CheckResult.FAIL.value in results:
        status = ValidationStatus.INVALID
    elif CheckResult.INCOMPLETE.value in results:
        status = ValidationStatus.INCOMPLETE
    else:
        status = ValidationStatus.VALID
    routing = _routing(status, context)
    reasons = sorted(item["reason_code"] for item in checks if item["result"] != CheckResult.PASS.value)
    document: dict[str, Any] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "validation_id": "merge-validation:pending",
        "merge_ref": context.merge.get("merge_id", "merge:invalid"),
        "merge_digest": _safe_merge_digest(context.merge),
        "bound_source_ref": context.bound_source.get("bound_source_id", "bound-source:invalid"),
        "bound_source_digest": _safe_bound_digest(context.bound_source),
        "validator_registry_version": VALIDATOR_REGISTRY_VERSION,
        "status": status.value,
        "routing": routing.value,
        "check_results": checks,
        "reason_codes": reasons,
    }
    document["validation_id"] = expected_merge_validation_id(document)
    validate_merge_validation_or_raise(document)
    return document


def _reference_integrity(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    errors = _validate_base_artifacts(
        context.merge, context.source_bytes, context.source_map, context.bound_source
    )
    gate = context.gate
    pairs = (
        (context.merge.get("trigger_template_ref"), gate.template_bundle.trigger_template_ref),
        (context.merge.get("trigger_template_digest"), gate.template_bundle.trigger_template_digest),
        (context.merge.get("trigger_template_interface_ref"), gate.template_manifest.get("manifest_id")),
        (context.merge.get("trigger_template_interface_digest"), gate.template_interface_digest),
        (context.merge.get("candidate_binding_ref"), gate.candidate_binding.get("binding_id")),
        (context.merge.get("candidate_binding_digest"), gate.candidate_binding_digest),
        (context.merge.get("candidate_binding_validation_ref"), gate.candidate_binding_validation.get("validation_id")),
        (context.merge.get("candidate_binding_validation_digest"), gate.candidate_binding_validation_digest),
    )
    if any(actual != expected for actual, expected in pairs):
        errors.append("Merge upstream ref/digest mismatch")
    return _from_errors(errors, "REFERENCES_VERIFIED", "REFERENCE_INTEGRITY_FAILED")


def _valid_binding_gate(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    validation = context.gate.candidate_binding_validation
    checks = validation.get("check_results", [])
    valid = (
        validation.get("status") == "VALID"
        and context.merge.get("candidate_binding_ref") == validation.get("candidate_binding_ref")
        and any(x.get("validator_type") == "REFERENCE_INTEGRITY" and x.get("result") == "PASS" for x in checks)
    )
    return _truth(valid, "VALID_BINDING_GATE_PASSED", "VALID_BINDING_GATE_FAILED")


def _slot_coverage(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    required = {
        slot["slot_ref"] for slot in context.gate.template_manifest["slots"] if slot["required"]
    }
    actual = Counter(item.get("template_slot_ref") for item in context.merge.get("slot_bindings", []))
    missing = sorted(ref for ref in required if actual[ref] == 0)
    return (
        (CheckResult.FAIL, "REQUIRED_SLOT_COVERAGE_FAILED", missing)
        if missing else (CheckResult.PASS, "REQUIRED_SLOTS_COVERED", [])
    )


def _slot_multiplicity(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    counts = Counter(item.get("template_slot_ref") for item in context.merge.get("slot_bindings", []))
    failures = []
    for slot in context.gate.template_manifest["slots"]:
        count = counts[slot["slot_ref"]]
        valid = {
            "ONE": count == 1 if slot["required"] else count <= 1,
            "ZERO_OR_ONE": count <= 1,
            "ONE_OR_MORE": count >= 1 if slot["required"] else True,
            "ZERO_OR_MORE": True,
        }[slot["multiplicity"]]
        if not valid:
            failures.append(slot["slot_ref"])
    return _truth(not failures, "SLOT_MULTIPLICITY_PRESERVED", "SLOT_MULTIPLICITY_FAILED", failures)


def _mapping_kind(
    context: ValidationContext,
    expected: Mapping[str, Any],
    kind: str,
    passed: str,
    failed: str,
) -> tuple[CheckResult, str, list[str]]:
    actual_items = [x for x in context.merge.get("slot_bindings", []) if x.get("candidate_element_kind") == kind]
    expected_items = [x for x in expected["slot_bindings"] if x["candidate_element_kind"] == kind]
    return _exact(actual_items, expected_items, passed, failed)


def _order(context: ValidationContext, expected: Mapping[str, Any]) -> tuple[CheckResult, str, list[str]]:
    expected_order = _obligation_refs(expected, "OPERATION_SEQUENCE_PRESERVED")
    actual_order = _obligation_refs(context.merge, "OPERATION_SEQUENCE_PRESERVED")
    source_order = [item.get("operation_binding_ref") for item in context.source_map.get("ordered_operation_records", [])]
    source_indexes = [item.get("sequence_index") for item in context.source_map.get("ordered_operation_records", [])]
    valid = actual_order == expected_order == source_order and source_indexes == list(range(len(expected_order)))
    return _truth(valid, "OPERATION_ORDER_PRESERVED", "OPERATION_ORDER_DRIFT")


def _structural(context: ValidationContext, expected: Mapping[str, Any]) -> tuple[CheckResult, str, list[str]]:
    valid = (
        context.merge.get("structural_obligations") == expected["structural_obligations"]
        and context.merge.get("anchor_bindings") == expected["anchor_bindings"]
    )
    return _truth(valid, "STRUCTURAL_OBLIGATIONS_PRESERVED", "STRUCTURAL_OBLIGATION_DRIFT")


def _adaptation_boundary(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    errors: list[str] = []
    fills = _resolved_fills(context.merge, context.source_bytes, context.source_map, errors)
    unresolved = set(context.bound_source.get("unresolved_hole_refs", []))
    declared = {hole["hole_id"] for hole in context.merge.get("adaptation_holes", [])}
    if unresolved | set(fills) != declared or unresolved & set(fills):
        errors.append("declared holes are not exactly partitioned into resolved/unresolved")
    for region in context.source_map.get("regions", []):
        if region.get("protected") and region.get("adaptation_hole_refs"):
            errors.append("adaptation hole overlaps a protected region")
        if not region.get("protected") and region.get("region_kind") != "ADAPTATION_HOLE":
            errors.append("unprotected undeclared region")
    return _from_errors(errors, "ADAPTATION_BOUNDARY_PRESERVED", "FORBIDDEN_ADAPTATION")


def _forbidden_drift(context: ValidationContext, expected: Mapping[str, Any]) -> tuple[CheckResult, str, list[str]]:
    keys = (
        "subject_realizations", "slot_bindings", "anchor_bindings", "identity_realizations",
        "observation_capture_bindings", "correlation_realizations", "structural_obligations",
    )
    drift = [key for key in keys if context.merge.get(key) != expected.get(key)]
    return _truth(not drift, "NO_FORBIDDEN_SEMANTIC_DRIFT", "FORBIDDEN_SEMANTIC_DRIFT", drift)


def _source_consistency(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    errors = _validate_base_artifacts(
        context.merge, context.source_bytes, context.source_map, context.bound_source
    )
    regions = {item.get("region_id"): item for item in context.source_map.get("regions", [])}
    base = regions.get("region:base-template")
    if base is None or base.get("canonical_digest") != context.merge.get("trigger_template_source_artifact_digest"):
        errors.append("base template protected region digest mismatch")
    elif any(base.get(key) for key in ("template_slot_refs", "merge_mapping_refs", "adaptation_hole_refs", "observation_capture_refs")):
        errors.append("base template region metadata drift")
    mapping_by_id = {item["mapping_id"]: item for item in context.merge.get("slot_bindings", [])}
    identity_by_id = {item["identity_realization_id"]: item for item in context.merge.get("identity_realizations", [])}
    mapping_region_by_id: dict[str, str] = {}
    identity_region_by_id: dict[str, str] = {}
    for region in context.source_map.get("regions", []):
        if not region.get("protected") or region.get("region_id") == "region:base-template":
            continue
        expected_payload = None
        mapping_refs = region.get("merge_mapping_refs", [])
        if len(mapping_refs) == 1 and mapping_refs[0] in mapping_by_id:
            mapping = mapping_by_id[mapping_refs[0]]
            expected_payload = _record_bytes("CIPHERLENS_MAPPING", mapping)
            mapping_region_by_id[mapping["mapping_id"]] = region["region_id"]
            expected_capture_refs = sorted(
                capture["capture_binding_id"]
                for capture in context.merge.get("observation_capture_bindings", [])
                if capture["observation_binding_ref"] == mapping["candidate_element_ref"]
            )
            if region.get("template_slot_refs") != [mapping["template_slot_ref"]]:
                errors.append(f"protected region {region.get('region_id')}: template-slot metadata drift")
            if sorted(region.get("observation_capture_refs", [])) != expected_capture_refs:
                errors.append(f"protected region {region.get('region_id')}: observation metadata drift")
        else:
            for identity in identity_by_id.values():
                if region.get("canonical_digest") == hashlib.sha256(_record_bytes("CIPHERLENS_IDENTITY", identity)).hexdigest():
                    expected_payload = _record_bytes("CIPHERLENS_IDENTITY", identity)
                    identity_region_by_id[identity["identity_realization_id"]] = region["region_id"]
                    if any(region.get(key) for key in ("template_slot_refs", "merge_mapping_refs", "adaptation_hole_refs", "observation_capture_refs")):
                        errors.append(f"protected region {region.get('region_id')}: identity-region metadata drift")
                    break
        if expected_payload is None:
            errors.append(f"protected region {region.get('region_id')}: not derivable from Merge")
            continue
        source_range = region["source_range"]
        actual_payload = context.source_bytes[source_range["byte_start"]:source_range["byte_end"]]
        if actual_payload != expected_payload:
            errors.append(f"protected region {region.get('region_id')}: deterministic payload drift")
    operation_mappings = {
        item["candidate_element_ref"]: item for item in mapping_by_id.values()
        if item["candidate_element_kind"] == "OPERATION"
    }
    expected_operations = []
    for sequence_index, operation_ref in enumerate(_obligation_refs(context.merge, "OPERATION_SEQUENCE_PRESERVED")):
        mapping = operation_mappings.get(operation_ref)
        if mapping is None or mapping["mapping_id"] not in mapping_region_by_id:
            errors.append(f"operation {operation_ref}: protected mapping region missing")
            continue
        expected_operations.append({
            "record_id": "operation-record:" + _short(operation_ref),
            "operation_binding_ref": operation_ref,
            "template_slot_ref": mapping["template_slot_ref"],
            "merge_mapping_ref": mapping["mapping_id"],
            "target_symbol_ref": mapping["target_semantic_ref"],
            "sequence_index": sequence_index,
            "region_ref": mapping_region_by_id[mapping["mapping_id"]],
        })
    if context.source_map.get("ordered_operation_records") != expected_operations:
        errors.append("SourceMap ordered-operation records drift")

    observation_mappings = {
        item["candidate_element_ref"]: item for item in mapping_by_id.values()
        if item["candidate_element_kind"] == "OBSERVATION"
    }
    expected_observations = []
    for capture in context.merge.get("observation_capture_bindings", []):
        mapping = observation_mappings.get(capture["observation_binding_ref"])
        if mapping is None or mapping["mapping_id"] not in mapping_region_by_id:
            errors.append(f"observation {capture['observation_binding_ref']}: protected mapping region missing")
            continue
        expected_observations.append({
            "record_id": "observation-record:" + _short(capture["observation_binding_ref"]),
            "observation_binding_ref": capture["observation_binding_ref"],
            "capture_binding_ref": capture["capture_binding_id"],
            "semantic_source_ref": capture["semantic_source_ref"],
            "acquisition_kind": capture["acquisition_kind"],
            "phase": capture["phase"],
            "region_ref": mapping_region_by_id[mapping["mapping_id"]],
        })
    if sorted(context.source_map.get("observation_capture_records", []), key=lambda x: x.get("record_id", "")) != sorted(expected_observations, key=lambda x: x["record_id"]):
        errors.append("SourceMap observation-capture records drift")

    expected_identities = []
    for identity in context.merge.get("identity_realizations", []):
        region_ref = identity_region_by_id.get(identity["identity_realization_id"])
        if region_ref is None:
            errors.append(f"identity {identity['identity_group_ref']}: protected storage region missing")
            continue
        expected_identities.append({
            "record_id": "identity-record:" + _short(identity["identity_group_ref"]),
            "identity_group_ref": identity["identity_group_ref"],
            "storage_ref": identity["storage_ref"],
            "subject_binding_refs": list(identity["subject_binding_refs"]),
            "region_ref": region_ref,
        })
    if sorted(context.source_map.get("identity_storage_records", []), key=lambda x: x.get("record_id", "")) != sorted(expected_identities, key=lambda x: x["record_id"]):
        errors.append("SourceMap identity-storage records drift")
    return _from_errors(errors, "SOURCE_BINDING_CONSISTENT", "SOURCE_BINDING_DRIFT")


def _completeness(context: ValidationContext) -> tuple[CheckResult, str, list[str]]:
    required = {
        hole["hole_id"] for hole in context.merge.get("adaptation_holes", []) if hole["required"]
    }
    unresolved = sorted(required.intersection(context.bound_source.get("unresolved_hole_refs", [])))
    if unresolved:
        return CheckResult.INCOMPLETE, "REQUIRED_SYNTAX_GLUE_UNRESOLVED", unresolved
    return CheckResult.PASS, "MERGE_SOURCE_COMPLETE", []


def _routing(status: ValidationStatus, context: ValidationContext) -> ValidationRouting:
    if status is ValidationStatus.INVALID:
        return ValidationRouting.WHOLE_BINDING_SWITCH
    if status is ValidationStatus.VALID:
        return ValidationRouting.EXECUTION_HANDOFF
    unresolved = set(context.bound_source.get("unresolved_hole_refs", []))
    resolvers = {
        hole["resolver"] for hole in context.merge.get("adaptation_holes", [])
        if hole["hole_id"] in unresolved and hole["required"]
    }
    if HoleResolver.DETERMINISTIC_ONLY.value in resolvers:
        return ValidationRouting.PROGRAMMATIC_COMPLETION
    if HoleResolver.PROPOSAL_ALLOWED.value in resolvers:
        return ValidationRouting.CONSTRAINED_ADAPTATION
    return ValidationRouting.WHOLE_BINDING_SWITCH


def _component(
    actual: Mapping[str, Any], expected: Mapping[str, Any], key: str, passed: str, failed: str
) -> tuple[CheckResult, str, list[str]]:
    return _exact(actual.get(key), expected.get(key), passed, failed)


def _exact(actual: Any, expected: Any, passed: str, failed: str) -> tuple[CheckResult, str, list[str]]:
    return _truth(actual == expected, passed, failed)


def _truth(
    value: bool, passed: str, failed: str, missing: list[str] | None = None
) -> tuple[CheckResult, str, list[str]]:
    return (CheckResult.PASS, passed, []) if value else (CheckResult.FAIL, failed, list(missing or []))


def _from_errors(errors: list[str], passed: str, failed: str) -> tuple[CheckResult, str, list[str]]:
    return _truth(not errors, passed, failed, [_error_ref(error) for error in errors])


def _error_ref(error: str) -> str:
    return "error:" + hashlib.sha256(error.encode("utf-8")).hexdigest()[:24]


def _obligation_refs(merge: Mapping[str, Any], kind: str) -> list[str]:
    for item in merge.get("structural_obligations", []):
        if item.get("obligation_type") == kind:
            return list(item.get("ordered_refs", []))
    return []


def _safe_merge_digest(value: Mapping[str, Any]) -> str:
    try:
        return merge_digest(value)
    except (TypeError, ValueError, KeyError):
        return hashlib.sha256(repr(sorted(value.items())).encode("utf-8")).hexdigest()


def _safe_bound_digest(value: Mapping[str, Any]) -> str:
    try:
        return bound_source_digest(value)
    except (TypeError, ValueError, KeyError):
        return hashlib.sha256(repr(sorted(value.items())).encode("utf-8")).hexdigest()
