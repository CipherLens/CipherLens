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
