"""Deterministic ELIGIBLE-only CandidateBinding construction."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from candidate_binding.canonical import expected_binding_id
from candidate_binding.model import BINDING_SCHEMA_VERSION, ConstructionRejected
from candidate_binding.validate import validate_candidate_binding_or_raise
from contract_miner.schema import canonical_vc_bytes, validate_vc_or_raise
from transfer_signature.canonical import canonical_evaluation_bytes, signature_digest, validate_evaluation_or_raise, validate_signature_or_raise
from transfer_signature.profile import profile_digest, validate_profile_or_raise
from trigger_template_interface.canonical import manifest_digest
from trigger_template_interface.validate import validate_manifest_or_raise
import hashlib


def construct_candidate_binding(
    *, contract: Mapping[str, Any], transfer_signature: Mapping[str, Any],
    template_manifest: Mapping[str, Any], target_profile: Mapping[str, Any],
    eligibility_evaluation: Mapping[str, Any], mappings: Mapping[str, Any],
    producer: str = "candidate_binding.construct", version: str = "v0.1",
) -> dict[str, Any]:
    """Construct from an explicit concrete mapping; performs no search or guessing."""

    validate_vc_or_raise(contract)
    validate_signature_or_raise(transfer_signature)
    validate_manifest_or_raise(template_manifest)
    validate_profile_or_raise(target_profile)
    validate_evaluation_or_raise(eligibility_evaluation)
    contract_digest = hashlib.sha256(canonical_vc_bytes(contract)).hexdigest()
    consistency_errors: list[str] = []
    if transfer_signature.get("source_contract_ref") != f"contract:{contract['contract_id']}" or transfer_signature.get("source_contract_digest") != contract_digest:
        consistency_errors.append("CONTRACT_TRANSFER_SIGNATURE_MISMATCH")
    if eligibility_evaluation.get("signature_id") != transfer_signature.get("signature_id"):
        consistency_errors.append("TRANSFER_SIGNATURE_EVALUATION_MISMATCH")
    if eligibility_evaluation.get("profile_id") != target_profile.get("profile_id"):
        consistency_errors.append("PROFILE_EVALUATION_MISMATCH")
    if consistency_errors:
        raise ConstructionRejected(consistency_errors)
    if eligibility_evaluation.get("eligibility") != "ELIGIBLE":
        raise ConstructionRejected([f"ELIGIBILITY_GATE_{eligibility_evaluation.get('eligibility', 'MISSING')}"])
    allowed_mapping_keys = {"subject_bindings", "operation_bindings", "input_bindings", "intervention_bindings", "continuity_bindings", "observation_bindings", "correlation_bindings", "verified_fact_refs", "evidence_refs"}
    unknown = set(mappings) - allowed_mapping_keys
    missing = allowed_mapping_keys - set(mappings)
    if unknown or missing:
        raise ConstructionRejected([f"explicit mappings missing={sorted(missing)!r} unknown={sorted(unknown)!r}"])
    result: dict[str, Any] = {
        "schema_version": BINDING_SCHEMA_VERSION,
        "binding_id": "binding:pending",
        "source_contract_ref": f"contract:{contract['contract_id']}",
        "source_contract_digest": contract_digest,
        "transfer_signature_ref": f"transfer-signature:{transfer_signature['signature_id']}",
        "transfer_signature_digest": signature_digest(transfer_signature),
        "trigger_template_ref": template_manifest["trigger_template_ref"],
        "trigger_template_digest": template_manifest["trigger_template_digest"],
        "target_profile_ref": f"target-profile:{target_profile['profile_id']}",
        "target_profile_digest": profile_digest(target_profile),
        "eligibility_evaluation_ref": f"eligibility-evaluation:{transfer_signature['signature_id']}:{target_profile['profile_id']}",
        "eligibility_evaluation_digest": hashlib.sha256(canonical_evaluation_bytes(eligibility_evaluation)).hexdigest(),
        "target_scope": deepcopy(dict(target_profile["target_scope"])),
        **{key: deepcopy(list(mappings[key])) for key in allowed_mapping_keys if key.endswith("_bindings")},
        "construction": {"producer": producer, "version": version, "verified_fact_refs": sorted(dict.fromkeys(mappings["verified_fact_refs"])), "evidence_refs": sorted(dict.fromkeys(mappings["evidence_refs"]))},
    }
    result["binding_id"] = expected_binding_id(result)
    validate_candidate_binding_or_raise(result)
    return result
