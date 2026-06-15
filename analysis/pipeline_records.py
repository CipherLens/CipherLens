"""Record helpers for the dry-run end-to-end mining orchestrator."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def stage_record(
    stage_id: str,
    stage_name: str,
    owner_module: str,
    input_artifacts: list[str],
    output_artifacts: list[str],
    status: str,
    blocked_by: list[str],
    uses_llm: bool,
    llm_allowed_output: str,
    allowed_to_execute_now: bool,
    notes: list[str],
) -> dict[str, Any]:
    return {
        "stage_id": stage_id,
        "stage_name": stage_name,
        "owner_module": owner_module,
        "input_artifacts": input_artifacts,
        "output_artifacts": output_artifacts,
        "status": status,
        "blocked_by": blocked_by,
        "uses_llm": uses_llm,
        "llm_allowed_output": llm_allowed_output,
        "allowed_to_execute_now": allowed_to_execute_now,
        "notes": notes,
    }


def family_state_record(family: str, status: str, stages: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "family": family,
        "status": status,
        "generated_at": now_iso(),
        "stages": stages,
        "summary": summary,
    }
