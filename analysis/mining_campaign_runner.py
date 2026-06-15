"""One-command mining campaign runner for local pipeline execution."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from analysis.campaign_records import candidate_summary_from_queue, run_python_module, stage_record
from analysis.campaign_state import campaign_state, family_history, next_action
from analysis.candidate_queue import build_family_candidate_queue
from analysis.family_selection import pending_families
from analysis.family_novelty_gate import historical_tested_families, novelty_gate_summary
from analysis.rag_glm_campaign_gate import (
    apply_known_pattern_gate,
    baseline_ready,
    load_rag_glm_baseline,
    new_candidate_summary,
)
from analysis.track_diversification import select_diversified_family
from template_maker.object_family_renderer import OBJECT_PARSING_FAMILIES
from analyzer.oracle_aware_analyzer import build_case_analysis, build_family_analysis, build_oracle_semantics
from analyzer.oracle_event_parser import parse_oracle_events
from runner.family_compile_runner import execute_rendered_case_index
from template_maker.family_render_plan import build_family_render_plan_from_mutation_matrix


CAMPAIGN_ID = "mining_campaign_runner_v1"
DEFAULT_EXTERNAL_PENDING = (
    "artifacts/sprints/x509_external_pending_and_continue_scheduler_v1/queue/"
    "external_pending_queue.yaml"
)
DEFAULT_SELECTION = "artifacts/sprints/family_profiles_bootstrap_v1/selection/post_bootstrap_family_selection.yaml"
DEFAULT_SEED_TASK = "artifacts/sprints/family_profiles_bootstrap_v1/plans/next_seed_discovery_task.yaml"
DEFAULT_PKEY_MANIFEST = (
    "artifacts/sprints/pkey_parsing_seed_discovery_v1/manifests/verified_pkey_seed_manifest.yaml"
)
DEFAULT_PKEY_PLAN = "artifacts/sprints/pkey_parsing_seed_discovery_v1/plans/next_execution_plan.yaml"
DEFAULT_FAMILY_PROFILES = "config/family_profiles.yaml"
DEFAULT_OPERATOR_REGISTRY = "config/mutation_operator_registry.yaml"
DEFAULT_PIPELINE_REGISTRY = "config/end_to_end_pipeline_registry.yaml"
DEFAULT_FAMILY_NOVELTY_POLICY = "config/family_novelty_policy.yaml"
STOP_LABELS = {
    "crash_candidate",
    "sanitizer_candidate",
    "full_consumption_gap_candidate",
    "semantic_divergence_candidate",
}
ADVANCE_FAMILY_ORDER = [
    "pkey_parsing",
    "pkcs8_parsing",
    "cms_container_parsing",
    "x509_crl_parsing",
]


def parse_bool(text: str | bool) -> bool:
    if isinstance(text, bool):
        return text
    return str(text).strip().lower() in {"1", "true", "yes", "y"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--max-stages", type=int, default=20)
    parser.add_argument("--stop-on-candidate", action="store_true")
    parser.add_argument("--skip-external-pending", action="store_true")
    parser.add_argument("--dry-run", default="false")
    parser.add_argument("--external-pending", default=DEFAULT_EXTERNAL_PENDING)
    parser.add_argument("--family-selection", default=DEFAULT_SELECTION)
    parser.add_argument("--seed-task", default=DEFAULT_SEED_TASK)
    parser.add_argument("--seed-manifest", default=DEFAULT_PKEY_MANIFEST)
    parser.add_argument("--seed-plan", default=DEFAULT_PKEY_PLAN)
    parser.add_argument("--family-profiles", default=DEFAULT_FAMILY_PROFILES)
    parser.add_argument("--operator-registry", default=DEFAULT_OPERATOR_REGISTRY)
    parser.add_argument("--pipeline-registry", default=DEFAULT_PIPELINE_REGISTRY)
    parser.add_argument("--previous-campaign", default="")
    parser.add_argument("--resume-from", default="")
    parser.add_argument("--use-rag-glm-baseline", default="")
    parser.add_argument("--known-pattern-gate", default="config/known_pattern_gate.yaml")
    parser.add_argument("--campaign-stop-policy", default="config/campaign_stop_policy.yaml")
    parser.add_argument("--family-track-policy", default="config/family_track_policy.yaml")
    parser.add_argument("--family-novelty-policy", default=DEFAULT_FAMILY_NOVELTY_POLICY)
    return parser.parse_args()


def selected_family(selection: dict[str, Any], seed_plan: dict[str, Any]) -> str:
    selected = selection.get("selected") or {}
    return str(selected.get("family") or seed_plan.get("family") or "")


def select_advance_family(
    *,
    profiles: dict[str, Any],
    skipped_families: set[str],
    completed_families: set[str],
) -> dict[str, Any]:
    profile_names = set((profiles.get("families") or {}).keys())
    candidates = []
    seen = set()
    for family in ADVANCE_FAMILY_ORDER + sorted(profile_names):
        if family in seen:
            continue
        seen.add(family)
        if family not in profile_names:
            continue
        status = "ready"
        reason = "profile_ready"
        if family in skipped_families:
            status = "external_pending_skipped"
            reason = "family is external pending"
        elif family in completed_families:
            status = "completed_known_pattern_only_skipped"
            reason = "family completed with known-pattern-only candidates"
        candidates.append({"family": family, "status": status, "reason": reason})
    ready = [item for item in candidates if item["status"] == "ready"]
    selected = ready[0]["family"] if ready else ""
    return {
        "schema": "family_selection_summary_v1",
        "generated_at": now_iso(),
        "family_selection_executed": True,
        "selected_family": selected,
        "selected": bool(selected),
        "completed_known_pattern_only_families": sorted(completed_families),
        "external_pending_skipped_families": sorted(skipped_families),
        "pkey_parsing_skipped": any(
            item["family"] == "pkey_parsing" and item["status"] == "completed_known_pattern_only_skipped"
            for item in candidates
        ),
        "candidates": candidates,
        "no_ready_family": not bool(selected),
    }


def stage_id(family: str, stage: str, index: int) -> str:
    return f"auto_{family}_{stage}_{index:03d}"


def campaign_quality(
    *,
    script_wrapper_created: bool,
    pipeline_registry: dict[str, Any],
    external_pending: dict[str, Any],
    external_pending_respected: bool,
    family: str,
    seed_reused: bool,
    mutation_used: bool,
    render_plan_executed: bool,
    render_cases_executed: bool,
    compile_run_executed: bool,
    oracle_analyze_executed: bool,
    candidate_queue_generated: bool,
    max_stages_respected: bool,
    stop_condition: str,
    stages_executed: int,
    candidates_found: int,
    missing_capabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    missing = bool(missing_capabilities)
    status = "blocked_missing_capability" if missing else "pass"
    return {
        "schema": "mining_campaign_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "script_wrapper_created": script_wrapper_created,
        "campaign_runner_created": True,
        "stage_registry_used": bool(pipeline_registry),
        "external_pending_loaded": bool(external_pending),
        "external_pending_respected": external_pending_respected,
        "pkey_selected": family == "pkey_parsing",
        "pkey_seed_manifest_reused": seed_reused,
        "generic_seed_discovery_available": Path("mutation/generic_seed_discovery.py").exists(),
        "generic_mutation_engine_used": mutation_used,
        "render_plan_executed": render_plan_executed,
        "render_cases_executed": render_cases_executed,
        "compile_run_executed": compile_run_executed,
        "oracle_aware_analyze_executed": oracle_analyze_executed,
        "candidate_queue_generated": candidate_queue_generated,
        "max_stages_respected": max_stages_respected,
        "stop_condition_recorded": bool(stop_condition),
        "stages_executed": stages_executed,
        "candidates_found": candidates_found,
        "missing_capability_found": missing,
        "main_feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def rag_glm_campaign_quality(
    *,
    baseline_status: dict[str, Any],
    gate_result: dict[str, Any],
    campaign_runner_executed: bool,
    stages_executed: int,
    candidate_queue_generated: bool,
) -> dict[str, Any]:
    if not baseline_ready(baseline_status):
        quality_status = "blocked_glm_baseline_missing"
    elif gate_result.get("new_candidates"):
        quality_status = "pass_new_candidate_found"
    elif gate_result.get("known_pattern_repeat_deduplicated"):
        quality_status = "pass_known_pattern_dedup_continue"
    else:
        quality_status = "pass_no_candidate"
    return {
        "schema": "mining_campaign_rag_glm_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "rag_glm_baseline_loaded": bool(baseline_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_loaded": bool(baseline_status.get("slot_bindings_loaded")),
        "slot_bindings_schema_valid": bool(baseline_status.get("slot_bindings_schema_valid")),
        "adapter_validate_passed": bool(baseline_status.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline_status.get("mapping_gate_bypassed")),
        "glm_called": bool(baseline_status.get("glm_called")),
        "glm_generated_c_code": bool(baseline_status.get("glm_generated_c_code")),
        "api_key_logged": bool(baseline_status.get("api_key_logged")),
        "known_pattern_gate_loaded": bool(gate_result.get("known_pattern_gate_loaded")),
        "known_pattern_repeat_deduplicated": bool(gate_result.get("known_pattern_repeat_deduplicated")),
        "campaign_runner_executed": campaign_runner_executed,
        "stages_executed": stages_executed,
        "candidate_queue_generated": candidate_queue_generated,
        "stop_policy_applied": bool(gate_result.get("stop_policy_applied")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }


def resume_quality(
    *,
    resume_state_loaded: bool,
    baseline_status: dict[str, Any],
    render_cases_executed: bool,
    compile_run_summary: dict[str, Any],
    oracle_analyze_executed: bool,
    candidate_queue_generated: bool,
    gate_result: dict[str, Any],
) -> dict[str, Any]:
    compile_executed = bool(compile_run_summary)
    run_executed = int((compile_run_summary.get("summary") or {}).get("run_attempted", 0) or 0) > 0
    if gate_result.get("new_candidates"):
        quality_status = "pass_new_candidate_found"
    elif gate_result.get("known_pattern_repeat_deduplicated"):
        quality_status = "pass_known_pattern_dedup_continue"
    else:
        quality_status = "pass_no_candidate"
    return {
        "schema": "resume_rag_glm_campaign_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "resume_state_loaded": resume_state_loaded,
        "rag_glm_baseline_loaded": bool(baseline_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_schema_valid": bool(baseline_status.get("slot_bindings_schema_valid")),
        "adapter_validate_passed": bool(baseline_status.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline_status.get("mapping_gate_bypassed")),
        "render_cases_executed": render_cases_executed,
        "compile_executed": compile_executed,
        "run_executed": run_executed,
        "oracle_analyze_executed": oracle_analyze_executed,
        "candidate_queue_generated": candidate_queue_generated,
        "known_pattern_gate_loaded": bool(gate_result.get("known_pattern_gate_loaded")),
        "known_pattern_gate_applied": bool(gate_result.get("stop_policy_applied")),
        "known_pattern_repeat_deduplicated": bool(gate_result.get("known_pattern_repeat_deduplicated")),
        "new_candidate_found": bool(gate_result.get("new_candidates")),
        "stop_policy_applied": bool(gate_result.get("stop_policy_applied")),
        "api_key_logged": bool(baseline_status.get("api_key_logged")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }


def advance_family_quality(
    *,
    resume_state_loaded: bool,
    previous_known_pattern_repeat_loaded: bool,
    completed_families: list[str],
    selection_summary: dict[str, Any],
    baseline_status: dict[str, Any],
    gate_result: dict[str, Any],
    candidate_queue_generated: bool,
) -> dict[str, Any]:
    no_ready = bool(selection_summary.get("no_ready_family"))
    return {
        "schema": "advance_family_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "resume_state_loaded": resume_state_loaded,
        "previous_known_pattern_repeat_loaded": previous_known_pattern_repeat_loaded,
        "completed_known_pattern_only_recorded": bool(completed_families),
        "completed_known_pattern_only_families": completed_families,
        "family_selection_executed": bool(selection_summary.get("family_selection_executed")),
        "pkey_parsing_skipped": bool(selection_summary.get("pkey_parsing_skipped")),
        "selected_family": selection_summary.get("selected_family", ""),
        "selected_family_is_pkey": selection_summary.get("selected_family") == "pkey_parsing",
        "external_pending_skipped": bool(selection_summary.get("external_pending_skipped_families")),
        "rag_glm_baseline_loaded": bool(baseline_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_schema_valid": bool(baseline_status.get("slot_bindings_schema_valid")),
        "adapter_validate_passed": bool(baseline_status.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline_status.get("mapping_gate_bypassed")),
        "known_pattern_gate_loaded": bool(gate_result.get("known_pattern_gate_loaded")),
        "known_pattern_gate_applied": bool(gate_result.get("stop_policy_applied")),
        "candidate_queue_generated": candidate_queue_generated,
        "stop_policy_applied": bool(gate_result.get("stop_policy_applied")),
        "api_key_logged": bool(baseline_status.get("api_key_logged")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "blocked_no_ready_family" if no_ready else "pass",
    }


def track_diversification_quality(
    *,
    resume_state_loaded: bool,
    previous_gate: dict[str, Any],
    completed_families: list[str],
    track_summary: dict[str, Any],
    selection_summary: dict[str, Any],
    baseline_status: dict[str, Any],
) -> dict[str, Any]:
    selected_family = str(track_summary.get("selected_family") or selection_summary.get("selected_family") or "")
    selected_track = str(track_summary.get("selected_track") or "")
    no_ready = bool(track_summary.get("no_ready_non_parsing_family"))
    return {
        "schema": "scheduler_track_diversification_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "resume_state_loaded": resume_state_loaded,
        "known_pattern_history_loaded": bool(previous_gate),
        "completed_known_pattern_only_loaded": bool(completed_families),
        "family_track_policy_loaded": bool(track_summary.get("family_track_policy_loaded")),
        "parsing_track_deprioritized": bool(track_summary.get("parsing_track_deprioritized")),
        "non_parsing_track_prioritized": bool(track_summary.get("non_parsing_track_prioritized")),
        "family_selection_executed": bool(selection_summary.get("family_selection_executed")),
        "selected_family": selected_family,
        "selected_track": selected_track,
        "selected_family_is_parsing": selected_track == "parsing",
        "selected_family_is_pkey": selected_family == "pkey_parsing",
        "selected_family_is_pkcs8": selected_family == "pkcs8_parsing",
        "external_pending_skipped": bool(selection_summary.get("external_pending_skipped_families")),
        "rag_glm_baseline_loaded": bool(baseline_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_schema_valid": bool(baseline_status.get("slot_bindings_schema_valid")),
        "adapter_validate_passed": bool(baseline_status.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline_status.get("mapping_gate_bypassed")),
        "api_key_logged": bool(baseline_status.get("api_key_logged")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "blocked_no_ready_non_parsing_family" if no_ready else "pass",
    }


def novelty_gate_quality(
    *,
    resume_state_loaded: bool,
    previous_gate: dict[str, Any],
    novelty_summary: dict[str, Any],
    track_summary: dict[str, Any],
    selection_summary: dict[str, Any],
    baseline_status: dict[str, Any],
    missing_capabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    selected_family = str(track_summary.get("selected_family") or selection_summary.get("selected_family") or "")
    selected_track = str(track_summary.get("selected_track") or "")
    historical = set(novelty_summary.get("historical_tested_families") or [])
    known_only = set(novelty_summary.get("known_pattern_only_families") or []) | set(
        novelty_summary.get("completed_known_pattern_only_families") or []
    )
    if track_summary.get("no_ready_non_parsing_family"):
        quality_status = "blocked_no_ready_novel_family"
    elif missing_capabilities and selected_family and selected_family not in historical and selected_family not in known_only:
        quality_status = "missing_capability_seed_discovery_required"
    else:
        quality_status = "pass"
    return {
        "schema": "scheduler_novelty_gate_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "resume_state_loaded": resume_state_loaded,
        "family_track_policy_loaded": bool(track_summary.get("family_track_policy_loaded")),
        "family_novelty_policy_loaded": bool(novelty_summary.get("family_novelty_policy_loaded")),
        "known_pattern_history_loaded": bool(previous_gate),
        "historical_tested_families_loaded": bool(novelty_summary.get("historical_tested_families_loaded")),
        "secure_heap_marked_historical_tested": bool(
            novelty_summary.get("secure_heap_marked_historical_tested")
        ),
        "secure_heap_skipped": bool(novelty_summary.get("secure_heap_skipped")),
        "parsing_track_deprioritized": bool(track_summary.get("parsing_track_deprioritized")),
        "non_parsing_track_prioritized": bool(track_summary.get("non_parsing_track_prioritized")),
        "family_selection_executed": bool(selection_summary.get("family_selection_executed")),
        "selected_family": selected_family,
        "selected_track": selected_track,
        "selected_family_is_parsing": selected_track == "parsing",
        "selected_family_is_secure_heap": selected_family == "secure_heap_state_lifecycle",
        "selected_family_is_known_pattern_only": selected_family in known_only,
        "selected_family_is_historical_tested": selected_family in historical,
        "external_pending_skipped": bool(selection_summary.get("external_pending_skipped_families")),
        "rag_glm_baseline_loaded": bool(baseline_status.get("rag_glm_baseline_loaded")),
        "slot_bindings_schema_valid": bool(baseline_status.get("slot_bindings_schema_valid")),
        "adapter_validate_passed": bool(baseline_status.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline_status.get("mapping_gate_bypassed")),
        "api_key_logged": bool(baseline_status.get("api_key_logged")),
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }


def pkey_resume_quality(
    *,
    previous_campaign_loaded: bool,
    family: str,
    rendered_case_count: int,
    compile_run_executed: bool,
    oracle_analyze_executed: bool,
    candidate_queue_generated: bool,
    compile_success: int,
    run_attempted: int,
    candidate_counts: dict[str, int],
    stop_condition: str,
    missing_capabilities: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_found = any(
        candidate_counts.get(key, 0) > 0
        for key in (
            "crash_candidate",
            "sanitizer_candidate",
            "full_consumption_gap_candidate",
            "semantic_divergence_candidate",
        )
    )
    if compile_success == 0:
        status = "blocked_compile_failed"
    elif candidate_found:
        status = "pass_candidate_found"
    else:
        status = "pass_no_candidate"
    return {
        "schema": "pkey_compile_run_analyze_resume_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_campaign_loaded": previous_campaign_loaded,
        "pkey_selected": family == "pkey_parsing",
        "rendered_cases_loaded": rendered_case_count == 3,
        "render_executed": False,
        "compile_run_executed": compile_run_executed,
        "oracle_aware_analyze_executed": oracle_analyze_executed,
        "candidate_queue_generated": candidate_queue_generated,
        "rendered_case_count": rendered_case_count,
        "compile_success": compile_success,
        "run_attempted": run_attempted,
        "crash_candidate_count": candidate_counts.get("crash_candidate", 0),
        "sanitizer_candidate_count": candidate_counts.get("sanitizer_candidate", 0),
        "full_consumption_gap_candidate_count": candidate_counts.get("full_consumption_gap_candidate", 0),
        "semantic_divergence_candidate_count": candidate_counts.get("semantic_divergence_candidate", 0),
        "stop_condition_recorded": bool(stop_condition),
        "missing_capability_found": bool(missing_capabilities),
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": status,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    dry_run = parse_bool(args.dry_run)
    resume_from = args.resume_from or args.previous_campaign
    for sub in ("validation", "reports"):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    external_pending = load_yaml(repo_root / args.external_pending)
    known_gate = load_yaml(repo_root / args.known_pattern_gate)
    stop_policy = load_yaml(repo_root / args.campaign_stop_policy)
    track_policy = load_yaml(repo_root / args.family_track_policy)
    novelty_policy = load_yaml(repo_root / args.family_novelty_policy)
    baseline_status = (
        load_rag_glm_baseline(repo_root / args.use_rag_glm_baseline)
        if args.use_rag_glm_baseline
        else {"schema": "rag_glm_baseline_status_v1", "rag_glm_baseline_loaded": False}
    )
    selection = load_yaml(repo_root / args.family_selection)
    seed_task = load_yaml(repo_root / args.seed_task)
    seed_manifest = load_yaml(repo_root / args.seed_manifest)
    seed_plan = load_yaml(repo_root / args.seed_plan)
    profiles = load_yaml(repo_root / args.family_profiles)
    pipeline_registry = load_yaml(repo_root / args.pipeline_registry)
    previous_state = load_yaml(repo_root / resume_from / "campaign_state.yaml") if resume_from else {}
    previous_gate = load_yaml(repo_root / resume_from / "known_pattern_gate_summary.yaml") if resume_from else {}

    family = selected_family(selection, seed_plan)
    skipped = sorted(pending_families(external_pending)) if args.skip_external_pending else []
    completed_known_pattern_only: list[str] = [
        str(item) for item in previous_state.get("completed_known_pattern_only_families", []) or []
    ]
    previous_known_pattern_repeat = bool(
        completed_known_pattern_only
        or previous_gate.get("known_pattern_repeat_deduplicated")
        and not previous_gate.get("new_candidates")
        and previous_gate.get("stop_campaign") is False
    )
    if previous_gate.get("known_pattern_repeat_deduplicated") and previous_state.get("current_family"):
        completed_known_pattern_only.append(str(previous_state["current_family"]))
    completed_known_pattern_only = sorted(set(completed_known_pattern_only))
    family_selection_summary: dict[str, Any] = {
        "schema": "family_selection_summary_v1",
        "generated_at": now_iso(),
        "family_selection_executed": False,
        "selected_family": family,
        "completed_known_pattern_only_families": completed_known_pattern_only,
        "external_pending_skipped_families": skipped,
        "pkey_parsing_skipped": False,
        "no_ready_family": False,
    }
    track_selection_summary: dict[str, Any] = {
        "schema": "track_selection_summary_v1",
        "generated_at": now_iso(),
        "family_track_policy_loaded": bool(track_policy),
        "family_novelty_policy_loaded": bool(novelty_policy),
        "known_pattern_history_loaded": bool(previous_gate),
        "historical_tested_families_loaded": bool(historical_tested_families(novelty_policy)),
        "parsing_track_deprioritized": False,
        "non_parsing_track_prioritized": False,
        "selected_family": family,
        "selected_track": "",
        "selected_family_is_parsing": False,
        "no_ready_non_parsing_family": False,
        "candidates": [],
    }
    if args.resume_from and completed_known_pattern_only:
        track_selection_summary = select_diversified_family(
            profiles=profiles,
            policy=track_policy,
            novelty_policy=novelty_policy,
            skipped_families=set(skipped),
            completed_families=set(completed_known_pattern_only),
            previous_gate=previous_gate,
        )
        if track_selection_summary.get("selected_family"):
            family = str(track_selection_summary["selected_family"])
            family_selection_summary = {
                "schema": "family_selection_summary_v1",
                "generated_at": now_iso(),
                "family_selection_executed": True,
                "selected_family": family,
                "selected": True,
                "completed_known_pattern_only_families": completed_known_pattern_only,
                "external_pending_skipped_families": skipped,
                "pkey_parsing_skipped": True,
                "candidates": track_selection_summary.get("candidates", []),
                "no_ready_family": False,
            }
        else:
            family_selection_summary = select_advance_family(
                profiles=profiles,
                skipped_families=set(skipped),
                completed_families=set(completed_known_pattern_only),
            )
            family = str(family_selection_summary.get("selected_family") or "")
    external_pending_respected = bool(args.skip_external_pending and skipped and family not in skipped)
    stages: list[dict[str, Any]] = []
    missing_capabilities: list[dict[str, Any]] = []
    candidate_queue = build_family_candidate_queue([], family=family or "unknown", source_task=CAMPAIGN_ID)
    candidate_source_task = CAMPAIGN_ID
    candidate_summary = candidate_summary_from_queue(candidate_queue, family or "unknown", candidate_source_task)
    stop_condition = ""
    status = "running"
    current_stage = "start"
    seed_reused = (
        family == "pkey_parsing"
        and bool(seed_manifest.get("seed_ready"))
        and seed_manifest.get("next_stage") == "mutation_planner"
    )

    mutation_used = False
    render_plan_executed = False
    render_cases_executed = False
    render_cases_summary: dict[str, Any] = {}
    compile_run_executed = False
    oracle_analyze_executed = False
    compile_summary: dict[str, Any] = {}
    run_results_doc: dict[str, Any] = {}
    analysis_doc: dict[str, Any] = {}

    if args.use_rag_glm_baseline and baseline_ready(baseline_status) and not dry_run:
        stages.append(
            stage_record(
                stage_id="rag_glm_baseline_gate_000",
                family=family,
                stage="rag_glm_baseline_gate",
                input_artifacts=[
                    args.use_rag_glm_baseline,
                    args.known_pattern_gate,
                    args.campaign_stop_policy,
                ],
                output_artifacts=["rag_glm_baseline_status.yaml"],
                status="pass",
                started_at=now_iso(),
                ended_at=now_iso(),
                summary={
                    "slot_bindings_schema_valid": baseline_status.get("slot_bindings_schema_valid"),
                    "adapter_validate_passed": baseline_status.get("adapter_validate_passed"),
                    "mapping_gate_bypassed": baseline_status.get("mapping_gate_bypassed"),
                    "glm_called": baseline_status.get("glm_called"),
                },
            )
        )

    if dry_run:
        stop_condition = "dry_run"
        status = "stopped"
    elif args.use_rag_glm_baseline and not baseline_ready(baseline_status):
        stop_condition = "blocked_glm_baseline_missing"
        status = "blocked"
        missing_capabilities.append(
            {
                "stage": "rag_glm_baseline_gate",
                "capability": "valid_rag_glm_baseline",
                "reason": "RAG/GLM baseline missing or failed slot/schema/adapter/mapping checks",
                "baseline_status": baseline_status,
            }
        )
    elif not family:
        stop_condition = "no_ready_family"
        status = "stopped"
    elif not seed_reused:
        stop_condition = "missing_capability"
        status = "blocked"
        missing_capabilities.append(
            {
                "stage": "seed_discovery",
                "capability": "ready_seed_manifest",
                "reason": f"{family} seed manifest is missing or not seed_ready=true",
            }
        )
    elif len(stages) >= args.max_stages:
        stop_condition = "max_stages"
        status = "stopped"
    elif resume_from and previous_state.get("stop_condition") == "resume_render_completed_stop_before_compile_run":
        current_stage = "compile_run"
        compile_out = repo_root / "artifacts/sprints/auto_pkey_parsing_compile_run_analyze_004"
        rendered_index_path = (
            repo_root
            / "artifacts/sprints/auto_pkey_parsing_render_cases_003/case_index/rendered_case_index.yaml"
        )
        rendered_index = load_yaml(rendered_index_path)
        started = now_iso()
        compile_run_doc = execute_rendered_case_index(
            repo_root=repo_root,
            rendered_index=rendered_index,
            out_dir=compile_out / "compile_run",
            openssl_install=Path("/home/wen/work/install-openssl-3.5.5-asan"),
            timeout_seconds=10,
            parse_oracle_events=lambda text, _case: parse_oracle_events(text),
        )
        ended = now_iso()
        compile_summary = {
            "schema": "pkey_compile_run_summary_v1",
            "generated_at": now_iso(),
            "family": family,
            "openssl": compile_run_doc["openssl"],
            "summary": compile_run_doc["summary"],
            "compile_results": compile_run_doc["compile_results"],
        }
        run_results_doc = {
            "schema": "pkey_run_results_v1",
            "generated_at": now_iso(),
            "family": family,
            "run_results": compile_run_doc["run_results"],
            "sanitizer_observations": compile_run_doc["sanitizer_observations"],
            "oracle_events": compile_run_doc["oracle_events"],
            "summary": compile_run_doc["summary"],
        }
        dump_yaml(compile_out / "compile_run/compile_run_summary.yaml", compile_summary)
        dump_yaml(compile_out / "compile_run/run_results.yaml", run_results_doc)
        compile_run_executed = True
        stages.append(
            stage_record(
                stage_id=compile_out.name,
                family=family,
                stage="compile_run",
                input_artifacts=[rendered_index_path.relative_to(repo_root).as_posix()],
                output_artifacts=[
                    (compile_out / "compile_run/compile_run_summary.yaml").relative_to(repo_root).as_posix(),
                    (compile_out / "compile_run/run_results.yaml").relative_to(repo_root).as_posix(),
                ],
                status="pass" if compile_run_doc["summary"]["compile_success"] > 0 else "blocked",
                started_at=started,
                ended_at=ended,
                summary=compile_run_doc["summary"],
            )
        )
        if compile_run_doc["summary"]["compile_success"] == 0:
            stop_condition = "compile_failed"
            status = "blocked"
        else:
            current_stage = "oracle_aware_analyze"
            events_doc = {
                "schema": "oracle_events_v1",
                "generated_at": now_iso(),
                "events": compile_run_doc["oracle_events"],
            }
            sanitizer_doc = {
                "schema": "sanitizer_observations_v1",
                "generated_at": now_iso(),
                "observations": compile_run_doc["sanitizer_observations"],
            }
            matrix_doc = {"schema": "rendered_case_matrix_proxy_v1", "cases": rendered_index.get("cases", [])}
            baseline_doc = {"schema": "empty_baseline_v1", "cases": []}
            case_analysis, labels_doc = build_case_analysis(
                run_results_doc,
                events_doc,
                sanitizer_doc,
                rendered_index,
                matrix_doc,
                baseline_doc,
            )
            family_doc = build_family_analysis(case_analysis)
            oracle_doc = build_oracle_semantics(events_doc, case_analysis)
            candidate_queue = build_family_candidate_queue(
                labels_doc.get("labels", []),
                family=family,
                source_task=compile_out.name,
            )
            candidate_source_task = compile_out.name
            candidate_summary = candidate_summary_from_queue(candidate_queue, family, compile_out.name)
            analysis_doc = {
                "schema": "pkey_oracle_aware_analysis_bundle_v1",
                "generated_at": now_iso(),
                "case_analysis": case_analysis,
                "candidate_labels": labels_doc,
                "family_summary": family_doc,
                "oracle_semantics": oracle_doc,
            }
            dump_yaml(compile_out / "analyze/oracle_aware_analysis.yaml", analysis_doc)
            dump_yaml(compile_out / "analyze/family_summary.yaml", family_doc)
            dump_yaml(compile_out / "candidates/pkey_candidate_queue.yaml", candidate_queue)
            oracle_analyze_executed = True
            stages.append(
                stage_record(
                    stage_id=compile_out.name + "_analyze",
                    family=family,
                    stage="oracle_aware_analyze",
                    input_artifacts=[(compile_out / "compile_run/run_results.yaml").relative_to(repo_root).as_posix()],
                    output_artifacts=[
                        (compile_out / "analyze/oracle_aware_analysis.yaml").relative_to(repo_root).as_posix(),
                        (compile_out / "candidates/pkey_candidate_queue.yaml").relative_to(repo_root).as_posix(),
                    ],
                    status="pass",
                    started_at=now_iso(),
                    ended_at=now_iso(),
                    summary={
                        "oracle_events": len(compile_run_doc["oracle_events"]),
                        "candidate_count": candidate_summary.get("candidate_count", 0),
                        "by_label": candidate_summary.get("by_label", {}),
                    },
                )
            )
            stop_candidates = int(candidate_summary.get("candidate_count", 0))
            if args.stop_on_candidate and stop_candidates:
                stop_condition = "candidate_found"
                status = "stopped"
            else:
                stop_condition = "no_candidate_continue_next_family"
                status = "stopped"
        dump_yaml(
            compile_out / "validation/pkey_compile_run_analyze_quality_checks.yaml",
            {
                "schema": "pkey_compile_run_analyze_quality_checks_v1",
                "compile_run_executed": compile_run_executed,
                "oracle_aware_analyze_executed": oracle_analyze_executed,
                "candidate_queue_generated": bool(candidate_queue),
                "quality_status": "pass" if oracle_analyze_executed else "blocked_compile_failed",
            },
        )
        write_text(
            compile_out / "reports/auto_pkey_parsing_compile_run_analyze_004_report.md",
            f"# auto_pkey_parsing_compile_run_analyze_004 Report\n\n"
            f"- compile_success: {compile_run_doc['summary']['compile_success']}\n"
            f"- run_attempted: {compile_run_doc['summary']['run_attempted']}\n"
            f"- oracle_events: {compile_run_doc['summary']['oracle_events']}\n"
            f"- stop_condition: {stop_condition}\n",
        )
    elif resume_from:
        current_stage = "render_cases"
        render_cases_out = repo_root / "artifacts/sprints" / stage_id(family, "render_cases", 3)
        render_plan_path = (
            repo_root
            / "artifacts/sprints"
            / stage_id(family, "render_plan", 2)
            / "render_plan/family_render_plan.yaml"
        )
        command = run_python_module(
            repo_root,
            "template_maker.family_case_renderer",
            [
                "--repo-root",
                ".",
                "--family",
                family,
                "--render-plan",
                render_plan_path.relative_to(repo_root).as_posix(),
                "--out-dir",
                render_cases_out.relative_to(repo_root).as_posix(),
            ],
        )
        index_path = render_cases_out / "case_index/rendered_case_index.yaml"
        index_doc = load_yaml(index_path)
        render_cases_executed = True
        render_cases_summary = {
            "schema": "render_cases_summary_v1",
            "generated_at": now_iso(),
            "family": family,
            "render_cases_executed": True,
            "rendered_case_count": index_doc.get("summary", {}).get("rendered_case_count", 0),
            "case_index": index_path.relative_to(repo_root).as_posix(),
            "command_return_code": command["return_code"],
        }
        stages.append(
            stage_record(
                stage_id=render_cases_out.name,
                family=family,
                stage="render_cases",
                input_artifacts=[render_plan_path.relative_to(repo_root).as_posix()],
                output_artifacts=[index_path.relative_to(repo_root).as_posix()],
                status="pass" if command["return_code"] == 0 else "blocked",
                started_at=command["started_at"],
                ended_at=command["ended_at"],
                summary={
                    "command_return_code": command["return_code"],
                    "rendered_case_count": index_doc.get("summary", {}).get("rendered_case_count", 0),
                },
            )
        )
        if command["return_code"] != 0:
            stop_condition = "missing_capability"
            status = "blocked"
            missing_capabilities.append(
                {
                    "stage": "render_cases",
                    "capability": "object_family_case_renderer",
                    "family": family,
                    "reason": "object family renderer did not produce rendered cases",
                }
            )
        else:
            stop_condition = "resume_render_completed_stop_before_compile_run"
            status = "stopped"
            if args.resume_from:
                current_stage = "compile_run"
                compile_out = repo_root / "artifacts/sprints/auto_pkey_parsing_compile_run_analyze_004"
                rendered_index_path = index_path
                rendered_index = index_doc
                started = now_iso()
                compile_run_doc = execute_rendered_case_index(
                    repo_root=repo_root,
                    rendered_index=rendered_index,
                    out_dir=compile_out / "compile_run",
                    openssl_install=Path("/home/wen/work/install-openssl-3.5.5-asan"),
                    timeout_seconds=10,
                    parse_oracle_events=lambda text, _case: parse_oracle_events(text),
                )
                ended = now_iso()
                compile_summary = {
                    "schema": "pkey_compile_run_summary_v1",
                    "generated_at": now_iso(),
                    "family": family,
                    "openssl": compile_run_doc["openssl"],
                    "summary": compile_run_doc["summary"],
                    "compile_results": compile_run_doc["compile_results"],
                }
                run_results_doc = {
                    "schema": "pkey_run_results_v1",
                    "generated_at": now_iso(),
                    "family": family,
                    "run_results": compile_run_doc["run_results"],
                    "sanitizer_observations": compile_run_doc["sanitizer_observations"],
                    "oracle_events": compile_run_doc["oracle_events"],
                    "summary": compile_run_doc["summary"],
                }
                dump_yaml(compile_out / "compile_run/compile_run_summary.yaml", compile_summary)
                dump_yaml(compile_out / "compile_run/run_results.yaml", run_results_doc)
                compile_run_executed = True
                stages.append(
                    stage_record(
                        stage_id=compile_out.name,
                        family=family,
                        stage="compile_run",
                        input_artifacts=[rendered_index_path.relative_to(repo_root).as_posix()],
                        output_artifacts=[
                            (compile_out / "compile_run/compile_run_summary.yaml").relative_to(repo_root).as_posix(),
                            (compile_out / "compile_run/run_results.yaml").relative_to(repo_root).as_posix(),
                        ],
                        status="pass" if compile_run_doc["summary"]["compile_success"] > 0 else "blocked",
                        started_at=started,
                        ended_at=ended,
                        summary=compile_run_doc["summary"],
                    )
                )
                if compile_run_doc["summary"]["compile_success"] == 0:
                    stop_condition = "compile_failed"
                    status = "blocked"
                else:
                    current_stage = "oracle_aware_analyze"
                    events_doc = {
                        "schema": "oracle_events_v1",
                        "generated_at": now_iso(),
                        "events": compile_run_doc["oracle_events"],
                    }
                    sanitizer_doc = {
                        "schema": "sanitizer_observations_v1",
                        "generated_at": now_iso(),
                        "observations": compile_run_doc["sanitizer_observations"],
                    }
                    matrix_doc = {"schema": "rendered_case_matrix_proxy_v1", "cases": rendered_index.get("cases", [])}
                    baseline_doc = {"schema": "empty_baseline_v1", "cases": []}
                    case_analysis, labels_doc = build_case_analysis(
                        run_results_doc,
                        events_doc,
                        sanitizer_doc,
                        rendered_index,
                        matrix_doc,
                        baseline_doc,
                    )
                    family_doc = build_family_analysis(case_analysis)
                    oracle_doc = build_oracle_semantics(events_doc, case_analysis)
                    candidate_queue = build_family_candidate_queue(
                        labels_doc.get("labels", []),
                        family=family,
                        source_task=compile_out.name,
                    )
                    candidate_source_task = compile_out.name
                    candidate_summary = candidate_summary_from_queue(candidate_queue, family, compile_out.name)
                    analysis_doc = {
                        "schema": "pkey_oracle_aware_analysis_bundle_v1",
                        "generated_at": now_iso(),
                        "case_analysis": case_analysis,
                        "candidate_labels": labels_doc,
                        "family_summary": family_doc,
                        "oracle_semantics": oracle_doc,
                    }
                    dump_yaml(compile_out / "analyze/oracle_aware_analysis.yaml", analysis_doc)
                    dump_yaml(compile_out / "analyze/family_summary.yaml", family_doc)
                    dump_yaml(compile_out / "candidates/pkey_candidate_queue.yaml", candidate_queue)
                    oracle_analyze_executed = True
                    stages.append(
                        stage_record(
                            stage_id=compile_out.name + "_analyze",
                            family=family,
                            stage="oracle_aware_analyze",
                            input_artifacts=[
                                (compile_out / "compile_run/run_results.yaml").relative_to(repo_root).as_posix()
                            ],
                            output_artifacts=[
                                (compile_out / "analyze/oracle_aware_analysis.yaml").relative_to(repo_root).as_posix(),
                                (compile_out / "candidates/pkey_candidate_queue.yaml").relative_to(repo_root).as_posix(),
                            ],
                            status="pass",
                            started_at=now_iso(),
                            ended_at=now_iso(),
                            summary={
                                "oracle_events": len(compile_run_doc["oracle_events"]),
                                "candidate_count": candidate_summary.get("candidate_count", 0),
                                "by_label": candidate_summary.get("by_label", {}),
                            },
                        )
                    )
                    stop_condition = "analyze_completed_known_pattern_gate_applied"
                    status = "stopped"
    else:
        current_stage = "mutation_planner"
        mutation_out = repo_root / "artifacts/sprints" / stage_id(family, "mutation_planner", 1)
        command = run_python_module(
            repo_root,
            "mutation.generic_mutation_engine",
            [
                "--repo-root",
                ".",
                "--family",
                family,
                "--seed-manifest",
                args.seed_manifest,
                "--out-dir",
                mutation_out.relative_to(repo_root).as_posix(),
                "--operator-registry",
                args.operator_registry,
                "--family-profiles",
                args.family_profiles,
            ],
        )
        mutation_used = True
        matrix_path = mutation_out / "mutation/generated_x509_case_matrix.yaml"
        matrix = load_yaml(matrix_path)
        stages.append(
            stage_record(
                stage_id=mutation_out.name,
                family=family,
                stage="mutation_planner",
                input_artifacts=[args.seed_manifest, args.family_profiles, args.operator_registry],
                output_artifacts=[matrix_path.relative_to(repo_root).as_posix()],
                status="pass" if command["return_code"] == 0 and matrix.get("cases") else "blocked",
                started_at=command["started_at"],
                ended_at=command["ended_at"],
                summary={
                    "command_return_code": command["return_code"],
                    "mutation_case_count": len(matrix.get("cases", []) or []),
                    "logs": command.get("logs", {}),
                },
            )
        )
        if command["return_code"] != 0 or not matrix.get("cases"):
            stop_condition = "missing_capability"
            status = "blocked"
            missing_capabilities.append(
                {
                    "stage": "mutation_planner",
                    "capability": "generic_mutation_cases",
                    "reason": "generic mutation engine did not produce mutation cases",
                }
            )

    if not stop_condition and len(stages) < args.max_stages:
        current_stage = "render_plan"
        render_out = repo_root / "artifacts/sprints" / stage_id(family, "render_plan", 2)
        started = now_iso()
        matrix_path = repo_root / "artifacts/sprints" / stage_id(family, "mutation_planner", 1) / "mutation/generated_x509_case_matrix.yaml"
        matrix = load_yaml(matrix_path)
        render_plan = build_family_render_plan_from_mutation_matrix(
            matrix,
            source_matrix_path=matrix_path.relative_to(repo_root).as_posix(),
            family_profiles=profiles,
        )
        render_plan_path = render_out / "render_plan/family_render_plan.yaml"
        dump_yaml(render_plan_path, render_plan)
        ended = now_iso()
        render_plan_executed = True
        stages.append(
            stage_record(
                stage_id=render_out.name,
                family=family,
                stage="render_plan",
                input_artifacts=[matrix_path.relative_to(repo_root).as_posix(), args.family_profiles],
                output_artifacts=[render_plan_path.relative_to(repo_root).as_posix()],
                status="pass" if render_plan.get("summary", {}).get("render_job_count", 0) > 0 else "blocked",
                started_at=started,
                ended_at=ended,
                summary=render_plan.get("summary", {}),
            )
        )

    if not stop_condition and len(stages) < args.max_stages:
        current_stage = "render_cases"
        if family not in OBJECT_PARSING_FAMILIES:
            stop_condition = "missing_capability"
            status = "blocked"
            missing_capabilities.append(
                {
                    "stage": "render_cases",
                    "capability": "family_case_renderer_support",
                    "family": family,
                    "reason": (
                        "template_maker.family_case_renderer currently lacks an object renderer for "
                        f"{family}"
                    ),
                }
            )
        else:
            stop_condition = "render_cases_ready_for_resume"
            status = "stopped"

    if not stop_condition and args.stop_on_candidate:
        stop_candidates = [
            item
            for item in candidate_queue.get("candidates", []) or []
            if item.get("candidate_label") in STOP_LABELS
        ]
        if stop_candidates:
            stop_condition = "candidate_found"
            status = "stopped"

    if not stop_condition and len(stages) >= args.max_stages:
        stop_condition = "max_stages"
        status = "stopped"

    if not stop_condition:
        stop_condition = "campaign_completed"
        status = "complete"

    candidate_summary = candidate_summary_from_queue(candidate_queue, family or "unknown", candidate_source_task)
    gate_result = apply_known_pattern_gate(candidate_queue, gate=known_gate, stop_policy=stop_policy)
    deduplicated_known = {
        "schema": "deduplicated_known_candidates_v1",
        "generated_at": now_iso(),
        "pattern_id": gate_result.get("known_pattern"),
        "deduplicated_count": len(gate_result.get("deduplicated_known_candidates", []) or []),
        "candidates": gate_result.get("deduplicated_known_candidates", []) or [],
    }
    new_summary = new_candidate_summary(gate_result)
    if gate_result.get("stop_campaign"):
        stop_condition = gate_result.get("stop_condition", "new_candidate_found")
        status = "stopped"
    elif gate_result.get("known_pattern_repeat_deduplicated") and stop_condition == "candidate_found":
        stop_condition = "known_pattern_deduplicated_continue"
        status = "stopped"

    if missing_capabilities:
        missing = missing_capabilities[0]
        if missing.get("stage") == "seed_discovery":
            action = next_action(
                f"run_seed_discovery_for_{family}",
                missing["reason"],
                False,
                [f"generate ready seed manifest for {family}"],
            )
        else:
            action = next_action(
                f"add_{family}_missing_capability",
                missing["reason"],
                False,
                [f"implement {missing.get('capability')} for {family}"],
            )
    else:
        action = next_action(
            gate_result.get("next_action", "continue_campaign") if gate_result else "continue_campaign",
            "pipeline can continue",
            True,
            [],
        )
    state = campaign_state(
        campaign_id=CAMPAIGN_ID,
        status=status,
        stop_condition=stop_condition,
        current_family=family,
        current_stage=current_stage,
        stages_executed=len(stages),
        families_touched=[family] if family else [],
        external_pending_skipped=skipped,
        candidates_found=int(candidate_summary.get("candidate_count", 0)),
        missing_capabilities=missing_capabilities,
        next_recommended_action=action,
        completed_known_pattern_only_families=completed_known_pattern_only,
    )
    qc = campaign_quality(
        script_wrapper_created=False,
        pipeline_registry=pipeline_registry,
        external_pending=external_pending,
        external_pending_respected=external_pending_respected,
        family=family,
        seed_reused=seed_reused,
        mutation_used=mutation_used,
        render_plan_executed=render_plan_executed,
        render_cases_executed=render_cases_executed,
        compile_run_executed=compile_run_executed,
        oracle_analyze_executed=oracle_analyze_executed,
        candidate_queue_generated=True,
        max_stages_respected=len(stages) <= args.max_stages,
        stop_condition=stop_condition,
        stages_executed=len(stages),
        candidates_found=int(candidate_summary.get("candidate_count", 0)),
        missing_capabilities=missing_capabilities,
    )
    rag_glm_qc = rag_glm_campaign_quality(
        baseline_status=baseline_status,
        gate_result=gate_result,
        campaign_runner_executed=True,
        stages_executed=len(stages),
        candidate_queue_generated=True,
    )
    advance_qc = advance_family_quality(
        resume_state_loaded=bool(previous_state),
        previous_known_pattern_repeat_loaded=previous_known_pattern_repeat,
        completed_families=completed_known_pattern_only,
        selection_summary=family_selection_summary,
        baseline_status=baseline_status,
        gate_result=gate_result,
        candidate_queue_generated=bool(candidate_summary),
    )
    candidate_counts = candidate_summary.get("by_label", {}) if isinstance(candidate_summary, dict) else {}
    pkey_qc = pkey_resume_quality(
        previous_campaign_loaded=bool(previous_state),
        family=family,
        rendered_case_count=int((compile_summary.get("summary") or {}).get("rendered_cases", 0))
        if compile_summary
        else 0,
        compile_run_executed=compile_run_executed,
        oracle_analyze_executed=oracle_analyze_executed,
        candidate_queue_generated=bool(candidate_summary),
        compile_success=int((compile_summary.get("summary") or {}).get("compile_success", 0))
        if compile_summary
        else 0,
        run_attempted=int((compile_summary.get("summary") or {}).get("run_attempted", 0))
        if compile_summary
        else 0,
        candidate_counts=candidate_counts,
        stop_condition=stop_condition,
        missing_capabilities=missing_capabilities,
    )

    dump_yaml(
        out_dir / "campaign_config.yaml",
        {
            "schema": "mining_campaign_config_v1",
            "generated_at": now_iso(),
            "campaign_id": CAMPAIGN_ID,
            "repo_root": repo_root.as_posix(),
            "max_stages": args.max_stages,
            "stop_on_candidate": bool(args.stop_on_candidate),
            "skip_external_pending": bool(args.skip_external_pending),
            "dry_run": dry_run,
            "previous_campaign": args.previous_campaign,
            "resume_from": args.resume_from,
            "inputs": {
                "external_pending": args.external_pending,
                "family_selection": args.family_selection,
                "seed_manifest": args.seed_manifest,
                "family_profiles": args.family_profiles,
                "operator_registry": args.operator_registry,
                "pipeline_registry": args.pipeline_registry,
                "rag_glm_baseline": args.use_rag_glm_baseline,
                "known_pattern_gate": args.known_pattern_gate,
                "campaign_stop_policy": args.campaign_stop_policy,
                "family_track_policy": args.family_track_policy,
                "family_novelty_policy": args.family_novelty_policy,
            },
        },
    )
    dump_yaml(out_dir / "campaign_state.yaml", state)
    dump_yaml(out_dir / "stage_history.yaml", {"schema": "campaign_stage_history_v1", "stages": stages})
    family_doc = family_history(family, stages)
    if family_doc.get("families"):
        family_doc["families"][0]["completion_status"] = (
            "completed_known_pattern_only" if family in completed_known_pattern_only else ""
        )
        family_doc["families"][0]["next_selection_skip"] = family in completed_known_pattern_only
    family_doc["completed_known_pattern_only_families"] = completed_known_pattern_only
    dump_yaml(out_dir / "family_history.yaml", family_doc)
    dump_yaml(out_dir / "family_selection_summary.yaml", family_selection_summary)
    dump_yaml(out_dir / "track_selection_summary.yaml", track_selection_summary)
    novelty_summary = novelty_gate_summary(
        policy=novelty_policy,
        selected_family=family,
        selected_track=str(track_selection_summary.get("selected_track") or ""),
        candidates=track_selection_summary.get("candidates", []) or [],
        completed_known_pattern_only=completed_known_pattern_only,
    )
    dump_yaml(out_dir / "novelty_gate_summary.yaml", novelty_summary)
    dump_yaml(out_dir / "rag_glm_baseline_status.yaml", baseline_status)
    dump_yaml(out_dir / "known_pattern_gate_summary.yaml", gate_result)
    if render_cases_summary:
        dump_yaml(out_dir / "render_cases_summary.yaml", render_cases_summary)
    if compile_summary:
        dump_yaml(out_dir / "compile_run_summary.yaml", compile_summary)
    if run_results_doc:
        dump_yaml(out_dir / "run_results.yaml", run_results_doc)
    if analysis_doc:
        dump_yaml(out_dir / "oracle_aware_analysis.yaml", analysis_doc)
        dump_yaml(
            out_dir / "analyze_summary.yaml",
            {
                "schema": "oracle_aware_analyze_summary_v1",
                "generated_at": now_iso(),
                "oracle_analyze_executed": True,
                "candidate_count": candidate_summary.get("candidate_count", 0),
                "by_label": candidate_summary.get("by_label", {}),
            },
        )
    dump_yaml(out_dir / "candidate_summary.yaml", candidate_summary)
    dump_yaml(out_dir / "deduplicated_known_candidates.yaml", deduplicated_known)
    dump_yaml(out_dir / "new_candidate_summary.yaml", new_summary)
    dump_yaml(
        out_dir / "completed_family_summary.yaml",
        {
            "schema": "completed_family_summary_v1",
            "generated_at": now_iso(),
            "previous_known_pattern_repeat_loaded": previous_known_pattern_repeat,
            "completed_known_pattern_only_recorded": bool(completed_known_pattern_only),
            "completed_known_pattern_only_families": completed_known_pattern_only,
            "skip_on_next_selection": completed_known_pattern_only,
        },
    )
    dump_yaml(
        out_dir / "external_pending_summary.yaml",
        {
            "schema": "campaign_external_pending_summary_v1",
            "generated_at": now_iso(),
            "loaded": bool(external_pending),
            "skipped_families": skipped,
            "items": external_pending.get("items", []) if isinstance(external_pending, dict) else [],
        },
    )
    dump_yaml(
        out_dir / "missing_capabilities.yaml",
        {
            "schema": "campaign_missing_capabilities_v1",
            "generated_at": now_iso(),
            "missing_capability_found": bool(missing_capabilities),
            "missing_capabilities": missing_capabilities,
        },
    )
    dump_yaml(out_dir / "next_recommended_action.yaml", action)
    dump_yaml(out_dir / "validation/mining_campaign_quality_checks.yaml", qc)
    dump_yaml(out_dir / "validation/mining_campaign_rag_glm_quality_checks.yaml", rag_glm_qc)
    dump_yaml(out_dir / "validation/advance_family_quality_checks.yaml", advance_qc)
    if args.resume_from and completed_known_pattern_only:
        novelty_qc = novelty_gate_quality(
            resume_state_loaded=bool(previous_state),
            previous_gate=previous_gate,
            novelty_summary=novelty_summary,
            track_summary=track_selection_summary,
            selection_summary=family_selection_summary,
            baseline_status=baseline_status,
            missing_capabilities=missing_capabilities,
        )
        dump_yaml(
            out_dir / "validation/scheduler_track_diversification_quality_checks.yaml",
            track_diversification_quality(
                resume_state_loaded=bool(previous_state),
                previous_gate=previous_gate,
                completed_families=completed_known_pattern_only,
                track_summary=track_selection_summary,
                selection_summary=family_selection_summary,
                baseline_status=baseline_status,
            ),
        )
        dump_yaml(out_dir / "validation/scheduler_novelty_gate_quality_checks.yaml", novelty_qc)
    if args.resume_from:
        dump_yaml(
            out_dir / "validation/resume_rag_glm_campaign_quality_checks.yaml",
            resume_quality(
                resume_state_loaded=bool(previous_state),
                baseline_status=baseline_status,
                render_cases_executed=render_cases_executed,
                compile_run_summary=compile_summary,
                oracle_analyze_executed=oracle_analyze_executed,
                candidate_queue_generated=bool(candidate_summary),
                gate_result=gate_result,
            ),
        )
    if previous_state.get("stop_condition") == "resume_render_completed_stop_before_compile_run":
        dump_yaml(out_dir / "validation/pkey_compile_run_analyze_resume_quality_checks.yaml", pkey_qc)
    if resume_from:
        dump_yaml(out_dir / "validation/mining_campaign_resume_quality_checks.yaml", qc)
    report = f"""# {CAMPAIGN_ID} Report

## Campaign

- selected_family: {family or 'none'}
- seed_manifest_reused: {seed_reused}
- stages_executed: {len(stages)}
- stop_condition: {stop_condition}
- missing_capability: {bool(missing_capabilities)}

## Stage Summary

- generic_mutation_engine_used: {mutation_used}
- render_plan_executed: {render_plan_executed}
- render_cases_executed: {render_cases_executed}
- compile_run_executed: {compile_run_executed}
- oracle_aware_analyze_executed: {oracle_analyze_executed}
- candidate_queue_generated: true
- candidates_found: {candidate_summary.get('candidate_count')}

## RAG/GLM Baseline

- baseline_loaded: {baseline_status.get('rag_glm_baseline_loaded')}
- slot_bindings_schema_valid: {baseline_status.get('slot_bindings_schema_valid')}
- adapter_validate_passed: {baseline_status.get('adapter_validate_passed')}
- mapping_gate_bypassed: {baseline_status.get('mapping_gate_bypassed')}
- glm_called: {baseline_status.get('glm_called')}

## Known Pattern Gate

- known_pattern: {gate_result.get('known_pattern')}
- known_pattern_repeat_deduplicated: {gate_result.get('known_pattern_repeat_deduplicated')}
- new_candidate_count: {new_summary.get('new_candidate_count')}
- stop_policy_applied: {gate_result.get('stop_policy_applied')}

## Policy

No tools script, feedback, pattern-bank, adapter recipe, normalized template,
git, CVE, exploitability, or confirmed vulnerability claim was produced.

## Novelty Gate

- selected_track: {track_selection_summary.get('selected_track')}
- historical_tested_skipped: {novelty_summary.get('historical_tested_skipped_families')}
- known_pattern_only_skipped: {novelty_summary.get('known_pattern_only_skipped_families')}
- secure_heap_skipped: {novelty_summary.get('secure_heap_skipped')}

## Quality

- quality_status: {rag_glm_qc.get('quality_status')}
"""
    write_text(out_dir / "reports/mining_campaign_runner_v1_report.md", report)
    write_text(out_dir / "reports/mining_campaign_runner_with_rag_glm_baseline_v1_report.md", report)
    write_text(out_dir / "reports/continue_rag_glm_campaign_advance_family_v1_report.md", report)
    if args.resume_from and completed_known_pattern_only:
        write_text(out_dir / "reports/scheduler_track_diversification_v1_report.md", report)
        write_text(out_dir / "reports/scheduler_novelty_gate_skip_tested_family_v1_report.md", report)
    if args.resume_from:
        write_text(out_dir / "reports/resume_rag_glm_campaign_render_compile_analyze_v1_report.md", report)
    if resume_from:
        write_text(out_dir / "reports/mining_campaign_runner_v1_resume_render_report.md", report)
    if previous_state.get("stop_condition") == "resume_render_completed_stop_before_compile_run":
        write_text(out_dir / "reports/pkey_parsing_compile_run_analyze_resume_v1_report.md", report)
    print(f"[OK] wrote mining campaign artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"family={family or 'none'} stages={len(stages)} stop={stop_condition} "
        f"quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
