"""RAG/GLM baseline and known-pattern gate helpers for campaign runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import load_yaml, now_iso
from analysis.known_pattern_gate import KNOWN_PATTERN_ID
from analysis.slot_filling_baseline import slot_schema_valid


NEW_STOP_LABELS = {
    "crash_candidate",
    "sanitizer_candidate",
    "semantic_divergence_candidate",
    "container_boundary_candidate",
    "lifecycle_divergence_candidate",
    "unknown_new_candidate",
}


def load_rag_glm_baseline(baseline_dir: Path) -> dict[str, Any]:
    slot_path = baseline_dir / "slot_filling/generated_slot_bindings.yaml"
    adapter_path = baseline_dir / "validation/adapter_validate_results.yaml"
    mapping_path = baseline_dir / "validation/mapping_gate_validate_results.yaml"
    glm_log_path = baseline_dir / "slot_filling/glm_invocation_log.yaml"
    quality_path = baseline_dir / "validation/glm_slot_filling_token_budget_quality_checks.yaml"
    slot_doc = load_yaml(slot_path)
    adapter_doc = load_yaml(adapter_path)
    mapping_doc = load_yaml(mapping_path)
    glm_log = load_yaml(glm_log_path)
    quality_doc = load_yaml(quality_path)
    return {
        "schema": "rag_glm_baseline_status_v1",
        "generated_at": now_iso(),
        "baseline_dir": baseline_dir.as_posix(),
        "rag_glm_baseline_loaded": baseline_dir.exists(),
        "slot_bindings_path": slot_path.as_posix(),
        "slot_bindings_loaded": bool(slot_doc.get("slot_bindings")),
        "slot_bindings_schema_valid": slot_schema_valid(slot_doc),
        "adapter_validate_path": adapter_path.as_posix(),
        "adapter_validate_passed": adapter_doc.get("status") == "pass"
        and bool(adapter_doc.get("adapter_validate_executed")),
        "mapping_gate_validate_path": mapping_path.as_posix(),
        "mapping_gate_reused": bool(mapping_doc),
        "mapping_gate_validate_executed": bool(mapping_doc.get("mapping_gate_validate_executed")),
        "mapping_gate_bypassed": bool(mapping_doc.get("mapping_gate_bypassed")),
        "glm_invocation_log_path": glm_log_path.as_posix(),
        "glm_called": bool(glm_log.get("glm_called")),
        "glm_request_count": int(glm_log.get("glm_request_count", 0) or 0),
        "glm_response_count": int(glm_log.get("glm_response_count", 0) or 0),
        "glm_generated_c_code": bool(quality_doc.get("glm_generated_c_code")),
        "api_key_logged": bool(glm_log.get("api_key_logged") or quality_doc.get("api_key_logged")),
        "quality_status": quality_doc.get("quality_status", ""),
    }


def baseline_ready(status: dict[str, Any]) -> bool:
    return all(
        [
            status.get("rag_glm_baseline_loaded"),
            status.get("slot_bindings_loaded"),
            status.get("slot_bindings_schema_valid"),
            status.get("adapter_validate_passed"),
            not status.get("mapping_gate_bypassed"),
            not status.get("glm_generated_c_code"),
            not status.get("api_key_logged"),
        ]
    )


def apply_known_pattern_gate(
    candidate_queue: dict[str, Any],
    *,
    gate: dict[str, Any],
    stop_policy: dict[str, Any],
) -> dict[str, Any]:
    patterns = gate.get("patterns") or []
    pattern = next(
        (item for item in patterns if item.get("pattern_id") == KNOWN_PATTERN_ID),
        patterns[0] if patterns else {},
    )
    observed = set(pattern.get("families_observed", []) or [])
    pending = set(pattern.get("families_pending", []) or [])
    deduplicated = []
    new_candidates = []
    for item in candidate_queue.get("candidates", []) or []:
        label = str(item.get("candidate_label") or item.get("label") or "")
        family = str(item.get("family") or "")
        if (
            label == "full_consumption_gap_candidate"
            and not bool(stop_policy.get("stop_on_repeat_known_full_consumption_gap"))
            and (not family or family in observed or family in pending)
        ):
            deduplicated.append(
                {
                    **item,
                    "pattern_id": KNOWN_PATTERN_ID,
                    "action": "deduplicate_and_continue",
                    "stop_campaign": False,
                }
            )
        elif label in NEW_STOP_LABELS:
            new_candidates.append({**item, "stop_campaign": True})
    stop_campaign = bool(new_candidates)
    if new_candidates:
        stop_condition = "new_candidate_found"
        next_action = "external_triage_new_candidate"
    elif deduplicated:
        stop_condition = "known_pattern_deduplicated_continue"
        next_action = "continue_campaign"
    else:
        stop_condition = "no_candidate_continue"
        next_action = "continue_campaign"
    return {
        "schema": "known_pattern_gate_summary_v1",
        "generated_at": now_iso(),
        "known_pattern_gate_loaded": bool(pattern),
        "known_pattern": pattern.get("pattern_id", KNOWN_PATTERN_ID),
        "repeat_candidate_action": "deduplicate_and_continue",
        "known_pattern_repeat_deduplicated": bool(deduplicated),
        "deduplicated_known_candidates": deduplicated,
        "new_candidates": new_candidates,
        "stop_on_new_semantic": bool(stop_policy.get("stop_on_new_semantic_class")),
        "stop_on_crash_or_sanitizer": bool(
            stop_policy.get("stop_on_crash_candidate") or stop_policy.get("stop_on_sanitizer_candidate")
        ),
        "stop_policy_applied": True,
        "stop_campaign": stop_campaign,
        "stop_condition": stop_condition,
        "next_action": next_action,
        "claim_policy": pattern.get("claim_policy", stop_policy.get("claim_policy", {})),
    }


def new_candidate_summary(gate_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "new_candidate_summary_v1",
        "generated_at": now_iso(),
        "new_candidate_found": bool(gate_result.get("new_candidates")),
        "new_candidate_count": len(gate_result.get("new_candidates", []) or []),
        "new_candidates": gate_result.get("new_candidates", []) or [],
        "stop_campaign": bool(gate_result.get("stop_campaign")),
    }
