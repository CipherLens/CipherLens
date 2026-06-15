"""Campaign state builders for automated mining runs."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def campaign_state(
    *,
    campaign_id: str,
    status: str,
    stop_condition: str,
    current_family: str,
    current_stage: str,
    stages_executed: int,
    families_touched: list[str],
    external_pending_skipped: list[str],
    candidates_found: int,
    missing_capabilities: list[dict[str, Any]],
    next_recommended_action: dict[str, Any],
    completed_known_pattern_only_families: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "campaign_state_v1",
        "generated_at": now_iso(),
        "campaign_id": campaign_id,
        "status": status,
        "stop_condition": stop_condition,
        "current_family": current_family,
        "current_stage": current_stage,
        "stages_executed": stages_executed,
        "families_touched": families_touched,
        "external_pending_skipped": external_pending_skipped,
        "completed_known_pattern_only_families": completed_known_pattern_only_families or [],
        "candidates_found": candidates_found,
        "missing_capabilities": missing_capabilities,
        "next_recommended_action": next_recommended_action,
    }


def family_history(family: str, stages: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "campaign_family_history_v1",
        "generated_at": now_iso(),
        "families": [
            {
                "family": family,
                "stages": [stage.get("stage") for stage in stages],
                "stage_count": len(stages),
                "last_stage": stages[-1].get("stage") if stages else "",
                "last_status": stages[-1].get("status") if stages else "",
            }
        ]
        if family
        else [],
    }


def next_action(action: str, reason: str, allowed_to_run_now: bool, required_work: list[str]) -> dict[str, Any]:
    return {
        "schema": "campaign_next_recommended_action_v1",
        "generated_at": now_iso(),
        "action": action,
        "reason": reason,
        "allowed_to_run_now": allowed_to_run_now,
        "required_work": required_work,
    }
