"""Fail-closed Merge to execution handoff."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from candidate_binding.canonical import candidate_binding_digest
from candidate_binding.validate import validate_candidate_binding_or_raise
from contract_miner.schema import canonical_vc_bytes, validate_vc_or_raise
from execution_model.canonical import artifact_digest, identify
from execution_model.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise
from template_binding_merge.canonical import (
    bound_source_digest, merge_digest, merge_validation_digest, semantic_digest as merge_semantic_digest, source_map_digest,
)
from template_binding_merge.validate import (
    validate_bound_source_or_raise, validate_merge_or_raise,
    validate_merge_validation_or_raise, validate_source_map_or_raise,
)


class HandoffRejected(ValueError):
    pass


def create_execution_handoff(
    contract: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    merge: Mapping[str, Any],
    merge_validation: Mapping[str, Any],
    bound_source: Mapping[str, Any],
    source_map: Mapping[str, Any],
    source_bytes: bytes,
) -> dict[str, Any]:
    """Accept only a fully validated immutable upstream lineage."""

    errors: list[str] = []
    try:
        validate_vc_or_raise(contract)
        validate_candidate_binding_or_raise(candidate_binding)
        validate_merge_or_raise(merge)
        validate_merge_validation_or_raise(merge_validation)
        validate_bound_source_or_raise(bound_source)
        validate_source_map_or_raise(source_map)
    except ValueError as exc:
        raise HandoffRejected(str(exc)) from exc

    contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
    binding_digest = candidate_binding_digest(candidate_binding)
    current_merge_digest = merge_digest(merge)
    current_validation_digest = merge_validation_digest(merge_validation)
    current_bound_digest = bound_source_digest(bound_source)
    current_map_digest = source_map_digest(source_map)
    source_digest = hashlib.sha256(source_bytes).hexdigest()

    checks = (
        (merge_validation.get("status") == "VALID", "merge validation is not VALID"),
        (merge_validation.get("routing") == "EXECUTION_HANDOFF", "merge routing is not EXECUTION_HANDOFF"),
        (not bound_source.get("unresolved_hole_refs"), "bound source has unresolved holes"),
        (candidate_binding.get("source_contract_ref") == f"contract:{contract.get('contract_id')}", "CandidateBinding Contract ref mismatch"),
        (candidate_binding.get("source_contract_digest") == contract_digest, "CandidateBinding Contract digest mismatch"),
        (merge.get("candidate_binding_ref") == candidate_binding.get("binding_id"), "Merge CandidateBinding ref mismatch"),
        (merge.get("candidate_binding_digest") == binding_digest, "Merge CandidateBinding digest mismatch"),
        (merge_validation.get("merge_ref") == merge.get("merge_id"), "MergeValidation Merge ref mismatch"),
        (merge_validation.get("merge_digest") == current_merge_digest, "MergeValidation Merge digest mismatch"),
        (merge_validation.get("bound_source_ref") == bound_source.get("bound_source_id"), "MergeValidation BoundSource ref mismatch"),
        (merge_validation.get("bound_source_digest") == current_bound_digest, "MergeValidation BoundSource digest mismatch"),
        (bound_source.get("merge_ref") == merge.get("merge_id") and bound_source.get("merge_digest") == current_merge_digest, "BoundSource Merge lineage mismatch"),
        (bound_source.get("source_map_ref") == source_map.get("source_map_id") and bound_source.get("source_map_digest") == current_map_digest, "BoundSource SourceMap lineage mismatch"),
        (bound_source.get("source_digest") == source_digest, "actual source bytes digest mismatch"),
        (source_map.get("merge_ref") == merge.get("merge_id") and source_map.get("merge_digest") == current_merge_digest, "SourceMap Merge lineage mismatch"),
    )
    errors.extend(message for passed, message in checks if not passed)

    capture_refs = sorted(item["capture_binding_id"] for item in merge.get("observation_capture_bindings", []))
    map_capture_refs = sorted(item["capture_binding_ref"] for item in source_map.get("observation_capture_records", []))
    identity_refs = sorted(item["identity_group_ref"] for item in merge.get("identity_realizations", []))
    map_identity_refs = sorted(item["identity_group_ref"] for item in source_map.get("identity_storage_records", []))
    operation_refs = sorted(item["operation_binding_ref"] for item in source_map.get("ordered_operation_records", []))
    merge_operation_refs = sorted(
        item["candidate_element_ref"] for item in merge.get("slot_bindings", [])
        if item.get("candidate_element_kind") == "OPERATION"
    )
    if capture_refs != map_capture_refs:
        errors.append("SourceMap observation capture records do not回连 Merge")
    if identity_refs != map_identity_refs:
        errors.append("SourceMap identity records do not回连 Merge")
    if operation_refs != merge_operation_refs:
        errors.append("SourceMap operation records do not回连 Merge")
    if errors:
        raise HandoffRejected("; ".join(sorted(errors)))

    seed_hints = {
        "target_scope": merge["target_scope"],
        "language": bound_source["language"],
        "renderer_id": bound_source["renderer_id"],
        "renderer_version": bound_source["renderer_version"],
    }
    seed_digest = merge_semantic_digest(seed_hints)
    if bound_source.get("build_spec_ref") != "build-spec:" + seed_digest or bound_source.get("build_spec_digest") != seed_digest:
        raise HandoffRejected("BoundSource build-intent seed mismatch")
    seed = {
        "seed_ref": bound_source["build_spec_ref"],
        "seed_digest": bound_source["build_spec_digest"],
        "hints": seed_hints,
    }
    document = identify({
        "schema_version": SCHEMA_VERSIONS["handoff"],
        "handoff_id": "pending",
        "contract_ref": candidate_binding["source_contract_ref"],
        "contract_digest": contract_digest,
        "candidate_binding_ref": candidate_binding["binding_id"],
        "candidate_binding_digest": binding_digest,
        "merge_ref": merge["merge_id"],
        "merge_digest": current_merge_digest,
        "merge_validation_ref": merge_validation["validation_id"],
        "merge_validation_digest": current_validation_digest,
        "bound_source_ref": bound_source["bound_source_id"],
        "bound_source_digest": current_bound_digest,
        "source_map_ref": source_map["source_map_id"],
        "source_map_digest": current_map_digest,
        "source_artifact_ref": bound_source["source_artifact_ref"],
        "source_artifact_digest": source_digest,
        "build_intent_seed": seed,
        "observation_capture_refs": capture_refs,
        "identity_refs": identity_refs,
        "operation_refs": operation_refs,
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document)
    artifact_digest(document)
    return document
