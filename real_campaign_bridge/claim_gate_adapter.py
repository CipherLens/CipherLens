"""B0 preflight adapter: it reports readiness evidence, not security claims."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from target_knowledge.canonical import identified
from .model import CampaignPreflightStatus


def evaluate_preflight(*, target_profiles: Sequence[Mapping[str, Any]], population_manifest: Mapping[str, Any], bridge_integrated: bool = False, execution_completed: bool = False) -> dict[str, Any]:
    blockers = []
    if any(item.get("validation_status") != "READY" for item in target_profiles):
        blockers.append("TARGET_KNOWLEDGE_NOT_VERIFIED_FOR_REAL_EXECUTION")
    if not bridge_integrated:
        blockers.append("RUNNER_CAPTURE_BRIDGE_NOT_INTEGRATED")
    if not execution_completed:
        blockers.append("NO_REAL_EXECUTION_TRACE")
    return identified({
        "schema_version": "cipherlens.real_campaign_claim_preflight.v0.1", "campaign_id": population_manifest["campaign_id"],
        "population_manifest_ref": population_manifest["manifest_id"], "status": CampaignPreflightStatus.PREPARED_FOR_7D_B0_FOUNDATION.value,
        "blocking_reasons": blockers, "real_execution_completed": execution_completed, "claim_gate_authority": "evaluation_claim_gate_unchanged",
        "allowed_next_stage": ["7D-B"], "forbidden_next_stage": ["7D-C_REAL_CLAIM"],
    }, "claim-preflight", "preflight_id")


def evaluate_7d_b_readiness(*, source_identities: Sequence[Mapping[str, Any]], build_profiles: Sequence[Mapping[str, Any]], target_profiles: Sequence[Mapping[str, Any]], differential_pairs: Sequence[Mapping[str, Any]], population_manifest: Mapping[str, Any], capture_readiness: Mapping[str, Any]) -> dict[str, Any]:
    """Gate only preparation completeness; it never authorizes 7D-C execution."""
    blockers: list[str] = []
    if not source_identities:
        blockers.append("SOURCE_IDENTITIES_MISSING")
    if not build_profiles:
        blockers.append("BUILD_PROFILES_MISSING")
    if not differential_pairs:
        blockers.append("DIFFERENTIAL_PAIR_MANIFESTS_MISSING")
    if len(population_manifest.get("units", [])) != 11:
        blockers.append("POPULATION_NOT_FROZEN_AT_11_UNITS")
    if capture_readiness.get("preparation_status") != CampaignPreflightStatus.PREPARED_FOR_7D_B.value:
        blockers.append("CAPTURE_PREPARATION_INCOMPLETE")
    if any(("p" + "ending") in str(value).lower() for value in [source_identities, build_profiles, target_profiles, differential_pairs, population_manifest, capture_readiness]):
        blockers.append("FAKE_OR_UNRESOLVED_DIGEST")
    status = CampaignPreflightStatus.B_BLOCKED_WITH_REASONS.value if blockers else CampaignPreflightStatus.PREPARED_FOR_7D_B.value
    return identified({
        "schema_version": "cipherlens.real_campaign_7d_b_readiness.v0.1",
        "campaign_id": population_manifest["campaign_id"], "status": status,
        "blocking_reasons": blockers, "source_identity_count": len(source_identities), "build_profile_count": len(build_profiles),
        "target_profile_count": len(target_profiles), "differential_pair_count": len(differential_pairs),
        "capture_readiness_ref": capture_readiness.get("capture_readiness_id"),
        "allowed_next_stage": ["7D-B"] if not blockers else [], "forbidden_next_stage": ["7D-C_REAL_CLAIM"],
        "real_execution_completed": False, "current_campaign_result": "NOT_GENERATED", "vulnerability_result": "NOT_GENERATED",
    }, "claim-7d-b-readiness", "readiness_id")


def evaluate_c0_bridge(*, population_manifest: Mapping[str, Any], profile_mapping: Mapping[str, Any], replay_lineage: Mapping[str, Any]) -> dict[str, Any]:
    """Gate C0 fixture validation without authorizing a real-campaign claim."""

    blockers: list[str] = []
    if len(population_manifest.get("units", [])) != 11:
        blockers.append("POPULATION_NOT_FROZEN_AT_11_UNITS")
    if profile_mapping.get("status") != "READY_FOR_BUILDSPEC_FIXTURE":
        blockers.append("BUILD_PROFILE_MAPPING_INCOMPLETE")
    if replay_lineage.get("classification") != "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN":
        blockers.append("REPLAY_LINEAGE_CLASSIFICATION_INVALID")
    if replay_lineage.get("relation_result") not in {"HOLDS", "BROKEN", "NOT_EVALUABLE"}:
        blockers.append("REPLAY_RELATION_EVALUATION_MISSING")
    status = "C0_BRIDGE_BLOCKED_WITH_REASONS" if blockers else "C0_BRIDGE_COMPLETED"
    return identified({
        "schema_version": "cipherlens.real_campaign_c0_claim_gate.v0.1",
        "campaign_id": population_manifest["campaign_id"],
        "status": status, "blocking_reasons": blockers,
        "population_manifest_ref": population_manifest["manifest_id"],
        "build_profile_mapping_ref": profile_mapping.get("mapping_id"),
        "replay_lineage_ref": replay_lineage.get("lineage_id"),
        "real_execution_completed": False,
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "report_real_number_allowed": False,
        "allowed_claim_levels": ["PIPELINE_VALIDATION_CLAIM", "ENGINEERING_VALIDATION_CLAIM"],
        "forbidden_claim_levels": ["CURRENT_CAMPAIGN_RESULT_CLAIM", "SECURITY_FINDING_CLAIM", "UPSTREAM_CONFIRMED_CLAIM"],
        "authority": "C0_REPLAY_ONLY_CLAIM_GATE",
    }, "claim-c0-readiness", "readiness_id")
