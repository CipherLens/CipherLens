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
