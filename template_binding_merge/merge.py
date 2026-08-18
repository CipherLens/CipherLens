"""Deterministic projection from a gated CandidateBinding into Merge v0.1."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Iterable, Mapping

from template_binding_merge.canonical import expected_merge_id
from template_binding_merge.model import (
    COMPLETION_REGISTRY_VERSION,
    MERGE_REGISTRY_VERSION,
    MERGE_SCHEMA_VERSION,
    AdaptationHoleType,
    CandidateElementKind,
    HoleResolver,
    MergeGateResult,
    RenderDisposition,
    RestrictedEditType,
    StructuralObligationType,
)
from template_binding_merge.validate import validate_merge_or_raise


_GROUPS = (
    ("subject_bindings", "subject_binding_id", "template_object_slot_refs", CandidateElementKind.SUBJECT),
    ("operation_bindings", "operation_binding_id", "template_call_slot_ref", CandidateElementKind.OPERATION),
    ("input_bindings", "input_binding_id", "template_input_slot_ref", CandidateElementKind.INPUT),
    ("intervention_bindings", "intervention_binding_id", "template_intervention_ref", CandidateElementKind.INTERVENTION),
    ("observation_bindings", "observation_binding_id", "template_observation_ref", CandidateElementKind.OBSERVATION),
)


def construct_merge(
    gate: MergeGateResult,
    *,
    additional_holes: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Create immutable semantic Merge content from one complete binding only."""

    manifest = gate.template_manifest
    binding = gate.candidate_binding
    slot_by_ref = {slot["slot_ref"]: slot for slot in manifest["slots"]}
    mappings = _slot_bindings(binding, slot_by_ref)
    subjects = _subject_realizations(binding)
    identities = _identity_realizations(binding)
    captures = _observation_capture_bindings(binding)
    correlations = _correlation_realizations(binding)
    anchors = _anchor_bindings(binding, manifest, mappings)
    obligations = _structural_obligations(binding, manifest, mappings, anchors)

    default_hole = _default_build_hole()
    holes = [default_hole, *(deepcopy(dict(item)) for item in additional_holes)]
    document: dict[str, Any] = {
        "schema_version": MERGE_SCHEMA_VERSION,
        "merge_id": "merge:pending",
        "trigger_template_ref": gate.template_bundle.trigger_template_ref,
        "trigger_template_digest": gate.template_bundle.trigger_template_digest,
        "trigger_template_source_artifact_ref": gate.template_bundle.source_artifact_ref,
        "trigger_template_source_artifact_digest": gate.template_bundle.source_artifact_digest,
        "trigger_template_interface_ref": manifest["manifest_id"],
        "trigger_template_interface_digest": gate.template_interface_digest,
        "candidate_binding_ref": binding["binding_id"],
        "candidate_binding_digest": gate.candidate_binding_digest,
        "candidate_binding_validation_ref": gate.candidate_binding_validation["validation_id"],
        "candidate_binding_validation_digest": gate.candidate_binding_validation_digest,
        "target_scope": deepcopy(binding["target_scope"]),
        "subject_realizations": subjects,
        "slot_bindings": mappings,
        "anchor_bindings": anchors,
        "identity_realizations": identities,
        "observation_capture_bindings": captures,
        "correlation_realizations": correlations,
        "adaptation_holes": holes,
        "structural_obligations": obligations,
        "construction": {
            "producer": "template_binding_merge.construct_merge",
            "registry_versions": [MERGE_REGISTRY_VERSION, COMPLETION_REGISTRY_VERSION],
            "verified_fact_refs": list(binding["construction"]["verified_fact_refs"]),
            "evidence_refs": list(binding["construction"]["evidence_refs"]),
            "canonical_upstream_refs": [
                gate.template_bundle.trigger_template_ref,
                manifest["manifest_id"],
                binding["binding_id"],
                gate.candidate_binding_validation["validation_id"],
            ],
        },
    }
    document["merge_id"] = expected_merge_id(document)
    validate_merge_or_raise(document)
    return document


def _slot_bindings(binding: Mapping[str, Any], slot_by_ref: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    pending: list[tuple[str, str, Mapping[str, Any], CandidateElementKind]] = []
    for group, id_key, slot_key, element_kind in _GROUPS:
        for element in binding.get(group, []):
            refs = element.get(slot_key, [])
            if isinstance(refs, str):
                refs = [refs]
            for slot_ref in refs:
                pending.append((str(slot_ref), str(element[id_key]), element, element_kind))

    counts: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for slot_ref, element_ref, element, element_kind in sorted(pending, key=lambda x: (x[0], x[1])):
        slot = slot_by_ref.get(slot_ref)
        slot_kind = slot["slot_kind"] if slot else "INPUT"
        occurrence = counts.get(slot_ref, 0)
        counts[slot_ref] = occurrence + 1
        mapping_key = f"{slot_ref}|{element_kind.value}|{element_ref}|{occurrence}"
        results.append({
            "mapping_id": _stable_ref("mapping", mapping_key),
            "template_slot_ref": slot_ref,
            "slot_kind": slot_kind,
            "candidate_element_kind": element_kind.value,
            "candidate_element_ref": element_ref,
            "target_semantic_ref": _target_semantic_ref(element_kind, element),
            "occurrence_index": occurrence,
            "render_disposition": (
                RenderDisposition.STRUCTURAL_ANCHOR.value
                if slot_kind in {"ORDER_ANCHOR", "STATE_ANCHOR"}
                else RenderDisposition.DIRECT_SUBSTITUTION.value
            ),
            "adaptation_hole_refs": [],
            "verified_fact_refs": list(element.get("verified_fact_refs", element.get("equivalence_fact_refs", []))),
            "evidence_refs": list(element.get("evidence_refs", [])),
        })
    return results


def _target_semantic_ref(kind: CandidateElementKind, element: Mapping[str, Any]) -> str:
    keys = {
        CandidateElementKind.SUBJECT: "target_subject_ref",
        CandidateElementKind.OPERATION: "target_symbol_ref",
        CandidateElementKind.INPUT: "target_parameter_ref",
        CandidateElementKind.INTERVENTION: "target_state_ref",
        CandidateElementKind.OBSERVATION: "semantic_source_ref",
    }
    value = element.get(keys[kind])
    if kind is CandidateElementKind.INTERVENTION and not value:
        value = element.get("target_parameter_ref") or element.get("target_operation_binding_ref")
    return str(value or element.get("intervention_kind") or "semantic:unspecified")


def _subject_realizations(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    operations = binding.get("operation_bindings", [])
    observations = binding.get("observation_bindings", [])
    result = []
    for subject in binding.get("subject_bindings", []):
        ref = subject["subject_binding_id"]
        result.append({
            "subject_realization_id": _stable_ref("subject-realization", ref),
            "subject_binding_ref": ref,
            "identity_group_ref": subject["identity_group_ref"],
            "storage_ref": _stable_ref("storage", subject["identity_group_ref"]),
            "target_subject_ref": subject["target_subject_ref"],
            "target_type_ref": subject["target_type_ref"],
            "ownership": subject["ownership"],
            "lifetime_region": subject["lifetime"],
            "operation_binding_refs": _ordered_operation_refs(
                op for op in operations
                if op.get("receiver_subject_binding_ref") == ref or ref in op.get("participant_binding_refs", [])
            ),
            "observation_binding_refs": sorted(
                obs["observation_binding_id"] for obs in observations
                if obs.get("target_subject_binding_ref") == ref or ref in obs.get("participant_binding_refs", [])
            ),
            "verified_fact_refs": list(subject["verified_fact_refs"]),
            "evidence_refs": list(subject["evidence_refs"]),
        })
    return result


def _identity_realizations(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for subject in binding.get("subject_bindings", []):
        groups.setdefault(subject["identity_group_ref"], []).append(subject)
    result = []
    for group_ref, subjects in sorted(groups.items()):
        subject_refs = {item["subject_binding_id"] for item in subjects}
        operations = [
            op for op in binding.get("operation_bindings", [])
            if op.get("receiver_subject_binding_ref") in subject_refs
            or subject_refs.intersection(op.get("participant_binding_refs", []))
        ]
        observations = [
            obs for obs in binding.get("observation_bindings", [])
            if obs.get("target_subject_binding_ref") in subject_refs
            or subject_refs.intersection(obs.get("participant_binding_refs", []))
        ]
        primary = sorted(subjects, key=lambda x: x["subject_binding_id"])[0]
        result.append({
            "identity_realization_id": _stable_ref("identity-realization", group_ref),
            "identity_group_ref": group_ref,
            "storage_ref": _stable_ref("storage", group_ref),
            "subject_binding_refs": sorted(subject_refs),
            "operation_binding_refs": _ordered_operation_refs(operations),
            "observation_binding_refs": sorted(x["observation_binding_id"] for x in observations),
            "lifetime_region": primary["lifetime"],
            "ownership": primary["ownership"],
            "evidence_refs": sorted({ref for item in subjects for ref in item["evidence_refs"]}),
        })
    return result


def _observation_capture_bindings(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for obs in binding.get("observation_bindings", []):
        ref = obs["observation_binding_id"]
        result.append({
            "capture_binding_id": _stable_ref("observation-capture", ref),
            "observation_binding_ref": ref,
            "contract_observable_ref": obs["contract_observable_ref"],
            "template_observation_slot_ref": obs["template_observation_ref"],
            "target_subject_binding_ref": obs["target_subject_binding_ref"],
            "target_operation_binding_ref": obs["target_operation_binding_ref"],
            "semantic_source_ref": obs["semantic_source_ref"],
            "acquisition_kind": obs["acquisition_kind"],
            "phase": obs["phase"],
            "value_type": obs["value_type"],
            "capture_code_ref": _stable_ref("capture-code", ref),
            "adaptation_hole_ref": None,
            "correlation_refs": list(obs["correlation_group_refs"]),
            "participant_refs": list(obs["participant_binding_refs"]),
            "execution_trace_field_ref": _stable_ref("trace-field", ref),
        })
    return result


def _correlation_realizations(binding: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = []
    for item in binding.get("correlation_bindings", []):
        ref = item["correlation_binding_id"]
        result.append({
            "correlation_realization_id": _stable_ref("correlation-realization", ref),
            "correlation_binding_ref": ref,
            "correlation_kind": item["correlation_kind"],
            "subject_binding_refs": list(item["subject_binding_refs"]),
            "operation_binding_refs": _order_refs_from_binding(binding, item["operation_binding_refs"]),
            "intervention_binding_refs": list(item["intervention_binding_refs"]),
            "observation_binding_refs": list(item["observation_binding_refs"]),
            "participant_refs": list(item["participant_binding_refs"]),
            "execution_trace_group_ref": _stable_ref("trace-group", ref),
            "verified_fact_refs": list(item["verified_fact_refs"]),
            "evidence_refs": list(item["evidence_refs"]),
        })
    return result


def _anchor_bindings(
    binding: Mapping[str, Any],
    manifest: Mapping[str, Any],
    mappings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ordered_ops = _ordered_operation_refs(binding.get("operation_bindings", []))
    continuity_refs = [x["continuity_binding_id"] for x in binding.get("continuity_bindings", [])]
    identities = sorted({x["identity_group_ref"] for x in binding.get("subject_bindings", [])})
    result = []
    for slot in manifest.get("slots", []):
        if slot["slot_kind"] not in {"ORDER_ANCHOR", "STATE_ANCHOR"}:
            continue
        refs = ordered_ops if slot["slot_kind"] == "ORDER_ANCHOR" else continuity_refs
        result.append({
            "anchor_binding_id": _stable_ref("anchor-binding", slot["slot_ref"]),
            "template_slot_ref": slot["slot_ref"],
            "slot_kind": slot["slot_kind"],
            "candidate_binding_refs": refs,
            "ordered_candidate_refs": ordered_ops,
            "identity_group_refs": identities,
            "merge_mapping_refs": [x["mapping_id"] for x in mappings if x["template_slot_ref"] == slot["slot_ref"]],
            "verified_fact_refs": [],
            "evidence_refs": [],
        })
    return result


def _structural_obligations(
    binding: Mapping[str, Any],
    manifest: Mapping[str, Any],
    mappings: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    required_slots = sorted(slot["slot_ref"] for slot in manifest["slots"] if slot["required"])
    subject_refs = sorted(x["subject_binding_id"] for x in binding["subject_bindings"])
    operation_refs = _ordered_operation_refs(binding["operation_bindings"])
    input_refs = sorted(x["input_binding_id"] for x in binding["input_bindings"])
    intervention_refs = sorted(x["intervention_binding_id"] for x in binding["intervention_bindings"])
    observation_refs = sorted(x["observation_binding_id"] for x in binding["observation_bindings"])
    correlation_refs = sorted(x["correlation_binding_id"] for x in binding["correlation_bindings"])
    identity_refs = sorted({x["identity_group_ref"] for x in binding["subject_bindings"]})
    template_anchors = sorted(x["template_slot_ref"] for x in anchors)
    mapping_refs = [x["mapping_id"] for x in mappings]
    continuity_refs = sorted(x["continuity_binding_id"] for x in binding["continuity_bindings"])
    followups = [
        x["operation_binding_id"] for x in sorted(binding["operation_bindings"], key=_operation_key)
        if x["binding_kind"] == "FOLLOWUP"
    ]

    intervention_phases = [
        f"intervention-phase:{x['intervention_binding_id']}:{x['application_phase']}"
        for x in sorted(binding["intervention_bindings"], key=lambda item: item["intervention_binding_id"])
    ]
    observation_phases = [
        f"observation-phase:{x['observation_binding_id']}:{x['phase']}"
        for x in sorted(binding["observation_bindings"], key=lambda item: item["observation_binding_id"])
    ]
    input_dependencies = [
        f"input-dependency:{x['input_binding_id']}:{x['target_operation_binding_ref']}"
        for x in sorted(binding["input_bindings"], key=lambda item: item["input_binding_id"])
    ]
    continuity_kinds = [
        f"continuity-kind:{x['continuity_binding_id']}:{x['continuity_kind']}"
        for x in sorted(binding["continuity_bindings"], key=lambda item: item["continuity_binding_id"])
    ]
    correlation_kinds = [
        f"correlation-kind:{x['correlation_binding_id']}:{x['correlation_kind']}"
        for x in sorted(binding["correlation_bindings"], key=lambda item: item["correlation_binding_id"])
    ]
    by_type = {
        StructuralObligationType.REQUIRED_SLOT_COVERAGE: (required_slots, mapping_refs),
        StructuralObligationType.OPERATION_SEQUENCE_PRESERVED: (operation_refs, operation_refs),
        StructuralObligationType.INTERVENTION_PHASE_PRESERVED: (intervention_phases, intervention_refs),
        StructuralObligationType.OBSERVATION_PHASE_PRESERVED: (observation_phases, observation_refs),
        StructuralObligationType.INPUT_DATA_DEPENDENCY_PRESERVED: (input_dependencies, input_refs),
        StructuralObligationType.SUBJECT_IDENTITY_PRESERVED: (subject_refs, identity_refs),
        StructuralObligationType.SAME_IDENTITY_ACROSS_OPERATIONS: (continuity_kinds, operation_refs),
        StructuralObligationType.FOLLOWUP_SEQUENCE_PRESERVED: (followups, operation_refs),
        StructuralObligationType.CORRELATION_RELATION_PRESERVED: (correlation_kinds, observation_refs),
        StructuralObligationType.CONTROL_FLOW_ANCHOR_PRESERVED: (template_anchors, operation_refs),
    }
    results = []
    for obligation_type in StructuralObligationType:
        typed_refs, ordered_refs = by_type[obligation_type]
        results.append({
            "obligation_id": _stable_ref("obligation", obligation_type.value),
            "obligation_type": obligation_type.value,
            "required": True,
            "typed_refs": list(typed_refs),
            "ordered_refs": list(ordered_refs),
            "identity_group_refs": identity_refs,
            "template_anchor_refs": template_anchors,
            "candidate_binding_refs": sorted(
                set(subject_refs + operation_refs + input_refs + intervention_refs + observation_refs + correlation_refs + continuity_refs)
            ),
            "advisory_description": obligation_type.value.lower().replace("_", " "),
        })
    return results


def _default_build_hole() -> dict[str, Any]:
    replacement = deterministic_hole_replacement(AdaptationHoleType.BUILD_METADATA.value, "hole:build-metadata")
    return {
        "hole_id": "hole:build-metadata",
        "hole_type": AdaptationHoleType.BUILD_METADATA.value,
        "required": True,
        "resolver": HoleResolver.DETERMINISTIC_ONLY.value,
        "syntax_kind": "C_COMMENT",
        "allowed_edit_types": [RestrictedEditType.FILL_HOLE.value],
        "allowed_replacement_digests": [hashlib.sha256(replacement.encode("utf-8")).hexdigest()],
        "semantic_guard_refs": ["guard:no-semantic-binding-change"],
        "target_region_ref": "region:build-metadata",
        "dependencies": [],
        "type_constraints": ["text=c-comment", f"registry={COMPLETION_REGISTRY_VERSION}"],
    }


def deterministic_hole_replacement(hole_type: str, hole_id: str) -> str:
    """Allowlisted stable completion output; it encodes no target semantic choice."""

    recipes = {
        AdaptationHoleType.BUILD_METADATA.value: (
            f"/* CipherLens deterministic build metadata; registry={COMPLETION_REGISTRY_VERSION}; hole={hole_id} */"
        ),
    }
    if hole_type not in recipes:
        raise KeyError(f"no deterministic recipe for {hole_type}")
    return recipes[hole_type]


def _ordered_operation_refs(operations: Iterable[Mapping[str, Any]]) -> list[str]:
    return [x["operation_binding_id"] for x in sorted(operations, key=_operation_key)]


def _order_refs_from_binding(binding: Mapping[str, Any], refs: Iterable[str]) -> list[str]:
    ref_set = set(refs)
    return _ordered_operation_refs(x for x in binding["operation_bindings"] if x["operation_binding_id"] in ref_set)


def _operation_key(item: Mapping[str, Any]) -> tuple[int, str]:
    return int(item["sequence_index"]), str(item["operation_binding_id"])


def _stable_ref(prefix: str, semantic: str) -> str:
    return f"{prefix}:{hashlib.sha256(semantic.encode('utf-8')).hexdigest()[:24]}"
