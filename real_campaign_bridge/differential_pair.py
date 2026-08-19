"""Differential pair manifests prevent accidental environment drift."""

from __future__ import annotations

from typing import Any, Mapping

from target_knowledge.canonical import identified
from target_knowledge.model import DIFFERENTIAL_PAIR_MANIFEST_SCHEMA
from .build_profile import _require_edge, same_source_root


def make_differential_pair_manifest(*, buggy_profile: Mapping[str, Any], fixed_profile: Mapping[str, Any], buggy_profile_artifact: Mapping[str, str], fixed_profile_artifact: Mapping[str, str], case_id: str, family: str, buggy_source: Mapping[str, str], fixed_source: Mapping[str, str], fix: Mapping[str, str], contract: Mapping[str, str], transfer_signature: Mapping[str, str], template: Mapping[str, str], input_artifact: Mapping[str, str], observation_schema_refs: list[str], fix_required_change: str, missing_artifacts: list[Mapping[str, str]] | None = None) -> dict[str, Any]:
    if not same_source_root(buggy_profile, fixed_profile):
        raise ValueError("differential profiles must share source identity")
    for key in ("compiler_identity", "architecture", "build_system_config", "compile_flags", "link_flags", "include_roots", "library_inputs", "sanitizer_profile", "dependencies", "controlled_environment", "timeout_seconds", "target_options", "input_artifact_digests"):
        if buggy_profile.get(key) != fixed_profile.get(key):
            raise ValueError(f"forbidden differential environment difference: {key}")
    for label, edge in (("buggy source", buggy_source), ("fixed source", fixed_source), ("fix", fix), ("contract", contract), ("transfer signature", transfer_signature), ("template", template), ("input artifact", input_artifact), ("buggy build profile", buggy_profile_artifact), ("fixed build profile", fixed_profile_artifact)):
        _require_edge(edge, label)
    return identified({
        "schema_version": DIFFERENTIAL_PAIR_MANIFEST_SCHEMA, "case_id": case_id, "family": family,
        "buggy_source_ref": buggy_source["ref"], "buggy_source_digest": buggy_source["digest"],
        "fixed_source_ref": fixed_source["ref"], "fixed_source_digest": fixed_source["digest"],
        "fix_ref": fix["ref"], "fix_digest": fix["digest"],
        "contract_ref": contract["ref"], "contract_digest": contract["digest"],
        "transfer_signature_ref": transfer_signature["ref"], "transfer_signature_digest": transfer_signature["digest"],
        "template_ref": template["ref"], "template_digest": template["digest"],
        "input_artifact_ref": input_artifact["ref"], "input_artifact_digest": input_artifact["digest"],
        "observation_schema_refs": observation_schema_refs,
        "buggy_profile_ref": buggy_profile_artifact["ref"], "buggy_profile_digest": buggy_profile_artifact["digest"],
        "fixed_profile_ref": fixed_profile_artifact["ref"], "fixed_profile_digest": fixed_profile_artifact["digest"],
        "allowed_difference_axes": ["source_revision", "fix_required_change"],
        "semantic_lock": {"compiler_identity": buggy_profile["compiler_identity"], "compile_flags": buggy_profile["compile_flags"], "include_roots": buggy_profile["include_roots"], "library_inputs": buggy_profile["library_inputs"], "build_system_config": buggy_profile["build_system_config"], "fix_required_change": fix_required_change},
        "missing_artifacts": list(missing_artifacts or [{"expected_future_artifact_type": "differential_witness_trace", "preparation_status": "MISSING_ARTIFACT"}]),
        "preparation_status": "PREPARED_FOR_7D_B", "validation_status": "PREPARED",
    }, "differential-pair", "pair_id")
