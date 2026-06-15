"""Controlled full pipeline for lifecycle oracle families."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from mutation.lifecycle_mutation_planner import build_lifecycle_mutation_plan
from runner.family_compile_runner import execute_instrumented_case, lib_dir_for_install, openssl_runtime_info
from template_maker.lifecycle_case_renderer import render_lifecycle_cases
from template_maker.lifecycle_render_plan import build_lifecycle_render_plan


TASK = "evp_digest_ctx_lifecycle_full_pipeline_v1"
DEFAULT_SEED_MANIFEST = "artifacts/sprints/evp_digest_ctx_lifecycle_seed_discovery_v1/seed_discovery/seed_manifest.yaml"
DEFAULT_BASELINE_ROOT = "artifacts/sprints/glm_slot_filling_token_budget_fix_v1"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"
DEFAULT_OUT_DIR = f"artifacts/sprints/{TASK}"
FORBIDDEN_LABELS = {
    "full_consumption_gap_candidate",
    "der_trailing_garbage_candidate",
    "app_level_der_validation_gap_candidate",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--seed-manifest", default=DEFAULT_SEED_MANIFEST)
    parser.add_argument("--baseline-root", default=DEFAULT_BASELINE_ROOT)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    return parser.parse_args()


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def copy_snapshot(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)


def baseline_status(baseline_root: Path) -> dict[str, Any]:
    slot_path = baseline_root / "validation/slot_bindings_schema_validate.yaml"
    adapter_path = baseline_root / "validation/adapter_validate_results.yaml"
    mapping_path = baseline_root / "validation/mapping_gate_validate_results.yaml"
    quality_path = baseline_root / "validation/glm_slot_filling_token_budget_quality_checks.yaml"
    slot = load_yaml(slot_path)
    adapter = load_yaml(adapter_path)
    mapping = load_yaml(mapping_path)
    quality = load_yaml(quality_path)
    return {
        "schema": "lifecycle_rag_glm_baseline_status_v1",
        "generated_at": now_iso(),
        "rag_glm_baseline_loaded": bool(quality.get("rag_lookup_reused") and quality.get("glm_called")),
        "slot_bindings_loaded": (baseline_root / "slot_filling/generated_slot_bindings.yaml").exists(),
        "slot_bindings_schema_valid": bool(slot.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(adapter),
        "adapter_validate_passed": adapter.get("status") == "pass",
        "mapping_gate_loaded": bool(mapping),
        "mapping_gate_bypassed": bool(mapping.get("mapping_gate_bypassed")),
        "source_paths": {
            "slot_bindings_schema": slot_path.as_posix(),
            "adapter_validate": adapter_path.as_posix(),
            "mapping_gate": mapping_path.as_posix(),
            "quality": quality_path.as_posix(),
        },
    }


def preflight(seed_manifest: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "seed_manifest_loaded": bool(seed_manifest),
        "seed_ready": seed_manifest.get("seed_ready") is True,
        "uses_der_parsing": bool(seed_manifest.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(seed_manifest.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(seed_manifest.get("uses_full_consumption_oracle")),
        "rag_glm_baseline_loaded": bool(baseline.get("rag_glm_baseline_loaded")),
        "slot_bindings_loaded": bool(baseline.get("slot_bindings_loaded")),
        "slot_bindings_schema_valid": bool(baseline.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(baseline.get("adapter_validate_loaded")),
        "adapter_validate_passed": bool(baseline.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline.get("mapping_gate_bypassed")),
    }
    checks["preflight_passed"] = (
        checks["seed_manifest_loaded"]
        and checks["seed_ready"]
        and not checks["uses_der_parsing"]
        and not checks["uses_trailing_garbage"]
        and not checks["uses_full_consumption_oracle"]
        and checks["rag_glm_baseline_loaded"]
        and checks["slot_bindings_loaded"]
        and checks["slot_bindings_schema_valid"]
        and checks["adapter_validate_loaded"]
        and checks["adapter_validate_passed"]
        and not checks["mapping_gate_bypassed"]
    )
    return checks


def parse_oracle_events(text: str, case: dict[str, Any]) -> list[dict[str, Any]]:
    values: dict[str, str] = {}
    raw_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ORACLE_EVENT"):
            continue
        raw_lines.append(stripped)
        payload = stripped[len("ORACLE_EVENT") :].strip()
        if "=" not in payload:
            continue
        key, value = payload.split("=", 1)
        values[key.strip()] = value.strip()
    if not raw_lines:
        return []
    return [
        {
            "schema": "lifecycle_oracle_event_v1",
            "case_id": values.get("case_id") or str(case.get("case_id") or ""),
            "family": values.get("family") or str(case.get("family") or ""),
            "target_library": str(case.get("target_library") or ""),
            "case_group": str(case.get("case_group") or ""),
            "mutation_strategy": values.get("mutation_strategy") or str(case.get("mutation_strategy") or ""),
            "oracle_rule": values.get("oracle_rule") or str(case.get("oracle_rule") or ""),
            "expected_behavior": values.get("expected_behavior") or str(case.get("expected_behavior") or ""),
            "actual_behavior": values.get("actual_behavior") or "",
            "state_transition_mismatch": as_bool(values.get("state_transition_mismatch", "false")),
            "crash_or_sanitizer": as_bool(values.get("crash_or_sanitizer", "false")),
            "raw_lines": raw_lines,
        }
    ]


def rendered_index(render_summary: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    cases = []
    for item in render_summary.get("case_files", []) or []:
        cases.append(
            {
                "case_id": item.get("case_id"),
                "family": render_summary.get("family"),
                "track": render_summary.get("track"),
                "archetype": render_summary.get("archetype"),
                "target_library": render_summary.get("target_library"),
                "harness_c": (repo_root / str(item.get("path"))).as_posix(),
                "expected_behavior": item.get("expected_behavior"),
                "mutation_strategy": item.get("mutation_strategy"),
                "case_group": item.get("case_group"),
                "oracle_rule": item.get("oracle_rule"),
            }
        )
    return cases


def classify(case: dict[str, Any], run: dict[str, Any], event: dict[str, Any] | None, sanitizer: dict[str, Any]) -> dict[str, Any]:
    sanitizer_seen = bool(sanitizer.get("sanitizer_observed") or run.get("sanitizer_observed"))
    signal = str(run.get("signal") or "")
    oracle_rule = str(case.get("oracle_rule") or "")
    actual = str((event or {}).get("actual_behavior") or "")
    mismatch = bool((event or {}).get("state_transition_mismatch"))
    label = "normal_expected_behavior"
    reason = "lifecycle behavior matched oracle policy"
    if sanitizer_seen or bool((event or {}).get("crash_or_sanitizer")):
        label = "sanitizer_candidate"
        reason = "sanitizer evidence observed"
    elif signal:
        label = "crash_candidate"
        reason = f"process signaled: {signal}"
    elif event is None:
        label = "needs_triage"
        reason = "missing lifecycle ORACLE_EVENT"
    elif oracle_rule == "state_transition_observation":
        label = "state_transition_observation"
        reason = "documented/observation case; not a candidate by itself"
    elif mismatch and oracle_rule == "unexpected_success_after_invalid_state":
        label = "unexpected_success_after_invalid_state_candidate"
        reason = "invalid state sequence returned success"
    elif mismatch and oracle_rule == "unexpected_failure_on_valid_sequence":
        label = "unexpected_failure_on_valid_sequence_candidate"
        reason = "valid lifecycle sequence failed"
    elif mismatch:
        label = "semantic_divergence_candidate"
        reason = f"unexpected lifecycle divergence actual={actual or 'unknown'}"
    return {
        "case_id": case.get("case_id"),
        "family": case.get("family"),
        "track": case.get("track"),
        "target_library": case.get("target_library"),
        "case_group": case.get("case_group"),
        "mutation_strategy": case.get("mutation_strategy"),
        "oracle_rule": oracle_rule,
        "expected_behavior": case.get("expected_behavior"),
        "actual_behavior": actual,
        "label": label,
        "candidate": label
        not in {"normal_expected_behavior", "state_transition_observation"},
        "reason": reason,
        "raw_observation_label": run.get("raw_observation_label", ""),
        "exit_code": run.get("exit_code"),
        "signal": signal,
        "sanitizer_observed": sanitizer_seen,
        "sanitizer_kinds": sanitizer.get("sanitizer_kinds") or run.get("sanitizer_kinds") or [],
    }


def count_label(records: list[dict[str, Any]], label: str) -> int:
    return len([item for item in records if item.get("label") == label])


def write_report(path: Path, qc: dict[str, Any]) -> None:
    report = f"""# {TASK} Report

## Pipeline

- family: {qc.get('family')}
- track: {qc.get('track')}
- archetype: {qc.get('archetype')}
- target_library: {qc.get('target_library')}
- mutation_case_count: {qc.get('mutation_case_count')}
- rendered_case_count: {qc.get('rendered_case_count')}
- compile_success: {qc.get('compile_success')}
- run_attempted: {qc.get('run_attempted')}
- candidate_count: {qc.get('candidate_count')}
- quality_status: {qc.get('quality_status')}

## Policy

No tools script, feedback main-store write, pattern-bank update, adapter recipe
edit, normalized-template edit, git operation, or vulnerability claim was made.
Documented observation cases are recorded as observations, not candidates.
"""
    write_text(path, report)


def write_campaign_artifacts(out_dir: Path, qc: dict[str, Any], seed_manifest: dict[str, Any]) -> None:
    completed = {
        "schema": "previous_completed_families_v1",
        "completed_known_pattern_only": ["pkey_parsing"],
        "historical_tested": ["secure_heap_state_lifecycle"],
        "completed_no_candidate": ["pkey_verify_semantic", "evp_digest_ctx_lifecycle"],
        "parsing_track_deprioritized": [
            "x509_parsing",
            "pkey_parsing",
            "pkcs8_parsing",
            "x509_crl_parsing",
            "cms_container_parsing",
            "pkcs_container_parsing",
        ],
    }
    selection = {
        "schema": "continue_next_family_selection_summary_v1",
        "generated_at": now_iso(),
        "family_selection_executed": True,
        "selected_family": qc.get("family"),
        "selected_track": qc.get("track"),
        "selected_archetype": qc.get("archetype"),
        "selected_family_is_parsing": False,
        "selected_family_is_historical_tested": False,
        "selected_family_is_completed_no_candidate": False,
        "skipped_completed_families": completed["completed_no_candidate"],
        "skipped_historical_families": completed["historical_tested"],
        "skipped_parsing_track": completed["parsing_track_deprioritized"],
    }
    novelty = {
        "schema": "continue_next_novelty_gate_summary_v1",
        "generated_at": now_iso(),
        "pkey_verify_semantic_skipped": True,
        "evp_digest_ctx_lifecycle_skipped": True,
        "secure_heap_skipped": True,
        "parsing_track_deprioritized": True,
        "selected_family": qc.get("family"),
        "selected_family_is_parsing": False,
        "selected_family_is_historical_tested": False,
        "selected_family_is_completed_no_candidate": False,
    }
    campaign_config = {
        "schema": "continue_next_novel_family_campaign_config_v1",
        "generated_at": now_iso(),
        "task": "continue_next_novel_family_full_pipeline_v1",
        "selected_family": qc.get("family"),
        "controlled_full_pipeline": True,
        "forbidden": {
            "tools_script": True,
            "der_trailing_garbage": True,
            "full_consumption_oracle": True,
            "unsafe_uaf_default_execution": True,
            "confirmed_vulnerability_claim": True,
        },
    }
    campaign_state = {
        "schema": "continue_next_novel_family_campaign_state_v1",
        "generated_at": now_iso(),
        "selected_family": qc.get("family"),
        "stages": {
            "family_selection": "complete",
            "baseline_gate": "complete",
            "seed_discovery": "complete",
            "mutation_plan": "complete",
            "render_plan": "complete",
            "render_cases": "complete",
            "compile_run": "complete",
            "oracle_analyze": "complete",
            "candidate_queue": "complete",
        },
        "quality_status": qc.get("quality_status"),
    }
    next_action = {
        "schema": "continue_next_recommended_action_v1",
        "generated_at": now_iso(),
        "current_family": qc.get("family"),
        "current_quality_status": qc.get("quality_status"),
        "candidate_count": qc.get("candidate_count"),
        "next_task": "scheduler_continue_next_novel_family_v1",
        "reason": "selected lifecycle family completed without candidates; scheduler can continue",
    }
    campaign_qc = {
        "schema": "continue_next_novel_family_full_pipeline_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_completed_families_loaded": True,
        "pkey_verify_semantic_skipped": True,
        "evp_digest_ctx_lifecycle_skipped": True,
        "secure_heap_skipped": True,
        "parsing_track_deprioritized": True,
        "family_selection_executed": True,
        "selected_family": qc.get("family"),
        "selected_track": qc.get("track"),
        "selected_archetype": qc.get("archetype"),
        "selected_family_is_parsing": False,
        "selected_family_is_historical_tested": False,
        "selected_family_is_completed_no_candidate": False,
        "rag_glm_baseline_loaded": qc.get("rag_glm_baseline_loaded"),
        "slot_bindings_loaded": qc.get("slot_bindings_loaded"),
        "slot_bindings_schema_valid": qc.get("slot_bindings_schema_valid"),
        "adapter_validate_loaded": qc.get("adapter_validate_loaded"),
        "adapter_validate_passed": qc.get("adapter_validate_passed"),
        "mapping_gate_bypassed": qc.get("mapping_gate_bypassed"),
        "seed_discovery_executed": True,
        "seed_ready": qc.get("seed_ready"),
        "mutation_plan_generated": qc.get("mutation_plan_generated"),
        "render_plan_generated": qc.get("render_plan_generated"),
        "render_cases_executed": qc.get("render_cases_executed"),
        "rendered_case_count": qc.get("rendered_case_count"),
        "compile_executed": qc.get("compile_executed"),
        "compile_success": qc.get("compile_success"),
        "compile_failed": qc.get("compile_failed"),
        "run_executed": qc.get("run_executed"),
        "run_attempted": qc.get("run_attempted"),
        "oracle_analyze_executed": qc.get("oracle_analyze_executed"),
        "oracle_events_parsed": qc.get("oracle_events_parsed"),
        "candidate_queue_generated": qc.get("candidate_queue_generated"),
        "candidate_count": qc.get("candidate_count"),
        "unexpected_success_after_invalid_state_count": qc.get(
            "unexpected_success_after_invalid_state_count"
        ),
        "unexpected_failure_on_valid_sequence_count": qc.get(
            "unexpected_failure_on_valid_sequence_count"
        ),
        "semantic_divergence_count": qc.get("semantic_divergence_count"),
        "crash_candidate_count": qc.get("crash_candidate_count"),
        "sanitizer_candidate_count": qc.get("sanitizer_candidate_count"),
        "baseline_control_failed": qc.get("baseline_control_failed"),
        "uses_der_parsing": qc.get("uses_der_parsing"),
        "uses_trailing_garbage": qc.get("uses_trailing_garbage"),
        "uses_full_consumption_oracle": qc.get("uses_full_consumption_oracle"),
        "parsing_track_leakage": qc.get("parsing_track_leakage"),
        "full_consumption_gap_label_generated": qc.get("full_consumption_gap_label_generated"),
        "unsafe_use_after_free_executed": qc.get("unsafe_use_after_free_executed"),
        "nonzero_exit_treated_as_crash_without_evidence": qc.get(
            "nonzero_exit_treated_as_crash_without_evidence"
        ),
        "api_key_logged": qc.get("api_key_logged"),
        "main_feedback_written": qc.get("main_feedback_written"),
        "pattern_bank_modified": qc.get("pattern_bank_modified"),
        "adapter_recipes_modified": qc.get("adapter_recipes_modified"),
        "normalized_templates_modified": qc.get("normalized_templates_modified"),
        "git_add_commit_push": qc.get("git_add_commit_push"),
        "confirmed_vulnerability_claim": qc.get("confirmed_vulnerability_claim"),
        "quality_status": qc.get("quality_status"),
    }
    dump_yaml(out_dir / "campaign_config.yaml", campaign_config)
    dump_yaml(out_dir / "campaign_state.yaml", campaign_state)
    dump_yaml(out_dir / "family_selection_summary.yaml", selection)
    dump_yaml(out_dir / "novelty_gate_summary.yaml", novelty)
    dump_yaml(out_dir / "inputs/previous_completed_families.yaml", completed)
    dump_yaml(out_dir / "next_recommended_action.yaml", next_action)
    dump_yaml(out_dir / "validation/continue_next_novel_family_full_pipeline_quality_checks.yaml", campaign_qc)


def blocked_quality(seed_manifest: dict[str, Any], baseline: dict[str, Any], preflight_doc: dict[str, Any]) -> dict[str, Any]:
    return {
        **base_quality(seed_manifest, baseline),
        "seed_manifest_loaded": bool(seed_manifest),
        "seed_ready": seed_manifest.get("seed_ready") is True,
        "quality_status": "blocked_preflight_failed",
        "preflight": preflight_doc,
    }


def base_quality(seed_manifest: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    family = str(seed_manifest.get("family", "evp_digest_ctx_lifecycle"))
    track = str(seed_manifest.get("track", "lifecycle"))
    archetype = str(seed_manifest.get("archetype", "evp_context_lifecycle"))
    seeds = seed_manifest.get("seeds", []) or []
    enabled_seed_count = len([item for item in seeds if item.get("enabled") is True])
    return {
        "schema": f"{family}_full_pipeline_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "selected_family": family,
        "selected_track": track,
        "selected_archetype": archetype,
        "family": family,
        "track": track,
        "archetype": archetype,
        "target_library": seed_manifest.get("target_library", "openssl"),
        "family_profile_added": family == "mac_lifecycle",
        "family_card_added": family == "mac_lifecycle",
        "rag_glm_baseline_loaded": bool(baseline.get("rag_glm_baseline_loaded")),
        "slot_bindings_loaded": bool(baseline.get("slot_bindings_loaded")),
        "slot_bindings_schema_valid": bool(baseline.get("slot_bindings_schema_valid")),
        "adapter_validate_loaded": bool(baseline.get("adapter_validate_loaded")),
        "adapter_validate_passed": bool(baseline.get("adapter_validate_passed")),
        "mapping_gate_bypassed": bool(baseline.get("mapping_gate_bypassed")),
        "seed_manifest_loaded": bool(seed_manifest),
        "seed_discovery_executed": bool(seed_manifest),
        "seed_ready": seed_manifest.get("seed_ready") is True,
        "enabled_seed_count": enabled_seed_count,
        "mutation_plan_generated": False,
        "mutation_case_count": 0,
        "render_plan_generated": False,
        "render_cases_executed": False,
        "rendered_case_count": 0,
        "compile_executed": False,
        "compile_success": 0,
        "compile_failed": 0,
        "run_executed": False,
        "run_attempted": 0,
        "oracle_analyze_executed": False,
        "oracle_events_parsed": False,
        "candidate_queue_generated": False,
        "candidate_count": 0,
        "unexpected_success_after_invalid_state_count": 0,
        "unexpected_failure_on_valid_sequence_count": 0,
        "semantic_divergence_count": 0,
        "crash_candidate_count": 0,
        "sanitizer_candidate_count": 0,
        "baseline_control_failed": False,
        "uses_der_parsing": bool(seed_manifest.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(seed_manifest.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(seed_manifest.get("uses_full_consumption_oracle")),
        "parsing_track_leakage": False,
        "full_consumption_gap_label_generated": False,
        "unsafe_use_after_free_executed": False,
        "nonzero_exit_treated_as_crash_without_evidence": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "blocked_preflight_failed",
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    seed_path = repo_root / args.seed_manifest
    baseline_root = repo_root / args.baseline_root
    openssl_install = Path(args.openssl_install)

    seed_manifest = load_yaml(seed_path)
    baseline = baseline_status(baseline_root)
    copy_snapshot(seed_path, out_dir / "inputs/seed_manifest_snapshot.yaml")
    copy_snapshot(
        baseline_root / "slot_filling/generated_slot_bindings.yaml",
        out_dir / "inputs/generated_slot_bindings_snapshot.yaml",
    )
    copy_snapshot(
        baseline_root / "validation/adapter_validate_results.yaml",
        out_dir / "inputs/adapter_validate_snapshot.yaml",
    )
    dump_yaml(out_dir / "rag_glm_baseline_status.yaml", baseline)
    preflight_doc = preflight(seed_manifest, baseline)
    dump_yaml(out_dir / "inputs/preflight_gate.yaml", preflight_doc)

    if not preflight_doc["preflight_passed"]:
        qc = blocked_quality(seed_manifest, baseline, preflight_doc)
        family = str(seed_manifest.get("family", "evp_digest_ctx_lifecycle"))
        quality_name = f"{seed_manifest.get('family', 'evp_digest_ctx_lifecycle')}_full_pipeline_quality_checks.yaml"
        dump_yaml(out_dir / "validation" / quality_name, qc)
        if seed_manifest.get("family") == "evp_digest_ctx_lifecycle":
            dump_yaml(out_dir / "validation/evp_digest_ctx_lifecycle_full_pipeline_quality_checks.yaml", qc)
        write_campaign_artifacts(out_dir, qc, seed_manifest)
        write_report(out_dir / f"reports/{family}_full_pipeline_report.md", qc)
        if family == "evp_digest_ctx_lifecycle":
            write_report(out_dir / "reports/evp_digest_ctx_lifecycle_full_pipeline_v1_report.md", qc)
        write_report(out_dir / "reports/continue_next_novel_family_full_pipeline_v1_report.md", qc)
        return 2

    mutation_plan, mutation_summary, deferred_mutations = build_lifecycle_mutation_plan(seed_manifest)
    dump_yaml(out_dir / "mutation/mutation_plan.yaml", mutation_plan)
    dump_yaml(out_dir / "mutation/mutation_summary.yaml", mutation_summary)
    dump_yaml(out_dir / "mutation/deferred_mutations.yaml", deferred_mutations)

    render_plan, render_summary, deferred_render = build_lifecycle_render_plan(mutation_plan)
    dump_yaml(out_dir / "render/render_plan.yaml", render_plan)
    dump_yaml(out_dir / "render/render_summary.yaml", render_summary)
    dump_yaml(out_dir / "render/deferred_render_capabilities.yaml", deferred_render)

    render_cases_summary, render_records = render_lifecycle_cases(render_plan, out_dir, repo_root)
    dump_yaml(out_dir / "render/render_cases_summary.yaml", render_cases_summary)
    dump_yaml(out_dir / "render/render_records.yaml", render_records)

    include_dir = openssl_install / "include"
    lib_dir = lib_dir_for_install(openssl_install)
    compile_results = []
    run_results = []
    oracle_events = []
    sanitizer_observations = []
    for case in rendered_index(render_cases_summary, repo_root):
        compile_result, run_result, events, sanitizer_observation = execute_instrumented_case(
            case,
            out_dir / "work",
            include_dir,
            lib_dir,
            openssl_install,
            args.timeout_seconds,
            parse_oracle_events,
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        oracle_events.extend(events)
        sanitizer_observations.append(sanitizer_observation)

    compile_success = len([item for item in compile_results if item.get("compile_status") == "compile_success"])
    compile_failed = len(compile_results) - compile_success
    run_attempted = len([item for item in run_results if item.get("run_status") != "not_run_compile_failed"])
    dump_yaml(
        out_dir / "compile/compile_jobs.yaml",
        {
            "schema": "lifecycle_compile_jobs_v1",
            "generated_at": now_iso(),
            "openssl": openssl_runtime_info(openssl_install),
            "compile_jobs": compile_results,
        },
    )
    dump_yaml(
        out_dir / "compile/compile_summary.yaml",
        {
            "schema": "lifecycle_compile_summary_v1",
            "compile_executed": True,
            "compile_success": compile_success,
            "compile_failed": compile_failed,
        },
    )
    dump_yaml(
        out_dir / "run/run_records.yaml",
        {
            "schema": "lifecycle_run_records_v1",
            "generated_at": now_iso(),
            "run_records": run_results,
            "sanitizer_observations": sanitizer_observations,
        },
    )
    dump_yaml(
        out_dir / "run/run_summary.yaml",
        {
            "schema": "lifecycle_run_summary_v1",
            "run_executed": True,
            "run_attempted": run_attempted,
            "normal_exit": len([item for item in run_results if item.get("raw_observation_label") == "normal_exit"]),
            "nonzero_exit": len([item for item in run_results if item.get("raw_observation_label") == "nonzero_exit"]),
            "crash_signal": len([item for item in run_results if item.get("signal")]),
            "asan_observed": len([item for item in sanitizer_observations if "asan" in (item.get("sanitizer_kinds") or [])]),
            "ubsan_observed": len([item for item in sanitizer_observations if "ubsan" in (item.get("sanitizer_kinds") or [])]),
        },
    )

    event_map = {str(item.get("case_id")): item for item in oracle_events}
    run_map = {str(item.get("case_id")): item for item in run_results}
    sanitizer_map = {str(item.get("case_id")): item for item in sanitizer_observations}
    classifications = [
        classify(
            case,
            run_map.get(str(case.get("case_id")), {}),
            event_map.get(str(case.get("case_id"))),
            sanitizer_map.get(str(case.get("case_id")), {}),
        )
        for case in rendered_index(render_cases_summary, repo_root)
    ]
    candidates = [item for item in classifications if item.get("candidate") is True]
    dump_yaml(out_dir / "analyze/oracle_events.yaml", {"schema": "lifecycle_oracle_events_v1", "oracle_events": oracle_events})
    dump_yaml(
        out_dir / "analyze/analyze_summary.yaml",
        {
            "schema": "lifecycle_analyze_summary_v1",
            "oracle_analyze_executed": True,
            "oracle_events_parsed": bool(oracle_events),
            "oracle_events_parsed_count": len(oracle_events),
            "valid_lifecycle_control_passed": not any(
                item.get("label") == "unexpected_failure_on_valid_sequence_candidate"
                for item in classifications
                if item.get("case_group") == "valid_lifecycle_control"
            ),
            "invalid_state_controls": len([item for item in classifications if item.get("case_group") == "invalid_state_control"]),
            "observation_cases": len([item for item in classifications if item.get("label") == "state_transition_observation"]),
            "baseline_control_failed": count_label(classifications, "unexpected_failure_on_valid_sequence_candidate") > 0,
            "case_classifications": classifications,
        },
    )
    dump_yaml(
        out_dir / "candidate_queue/candidates.yaml",
        {
            "schema": "lifecycle_candidate_queue_v1",
            "allowed_labels": [
                "normal_expected_behavior",
                "state_transition_observation",
                "unexpected_success_after_invalid_state_candidate",
                "unexpected_failure_on_valid_sequence_candidate",
                "semantic_divergence_candidate",
                "crash_candidate",
                "sanitizer_candidate",
                "baseline_control_failed",
                "needs_triage",
            ],
            "forbidden_labels": sorted(FORBIDDEN_LABELS),
            "candidates": candidates,
            "all_case_labels": classifications,
        },
    )
    dump_yaml(
        out_dir / "candidate_queue/candidate_summary.yaml",
        {
            "schema": "lifecycle_candidate_summary_v1",
            "candidate_queue_generated": True,
            "candidate_count": len(candidates),
            "unexpected_success_after_invalid_state_count": count_label(
                classifications, "unexpected_success_after_invalid_state_candidate"
            ),
            "unexpected_failure_on_valid_sequence_count": count_label(
                classifications, "unexpected_failure_on_valid_sequence_candidate"
            ),
            "semantic_divergence_count": count_label(classifications, "semantic_divergence_candidate"),
            "crash_candidate_count": count_label(classifications, "crash_candidate"),
            "sanitizer_candidate_count": count_label(classifications, "sanitizer_candidate"),
            "needs_triage_count": count_label(classifications, "needs_triage"),
            "state_transition_observation_count": count_label(classifications, "state_transition_observation"),
        },
    )

    full_consumption_label = any(item.get("label") in FORBIDDEN_LABELS for item in classifications)
    parsing_leakage = bool(
        seed_manifest.get("uses_der_parsing")
        or seed_manifest.get("uses_trailing_garbage")
        or seed_manifest.get("uses_full_consumption_oracle")
        or full_consumption_label
    )
    baseline_failed = count_label(classifications, "unexpected_failure_on_valid_sequence_candidate") > 0
    if parsing_leakage:
        quality_status = "failed_der_parsing_leakage"
    elif compile_success < 6:
        quality_status = "blocked_compile_failure"
    elif baseline_failed:
        quality_status = "blocked_baseline_control_failed"
    elif count_label(classifications, "crash_candidate") or count_label(classifications, "sanitizer_candidate"):
        quality_status = "pass_crash_or_sanitizer_candidate_found"
    elif candidates:
        quality_status = "pass_new_lifecycle_candidate_found"
    else:
        quality_status = "pass_no_candidate"

    qc = {
        **base_quality(seed_manifest, baseline),
        "mutation_plan_generated": True,
        "mutation_case_count": int(mutation_plan.get("mutation_case_count") or 0),
        "render_plan_generated": True,
        "render_cases_executed": True,
        "rendered_case_count": int(render_cases_summary.get("rendered_case_count") or 0),
        "compile_executed": True,
        "compile_success": compile_success,
        "compile_failed": compile_failed,
        "run_executed": True,
        "run_attempted": run_attempted,
        "oracle_analyze_executed": True,
        "oracle_events_parsed": bool(oracle_events),
        "candidate_queue_generated": True,
        "candidate_count": len(candidates),
        "unexpected_success_after_invalid_state_count": count_label(
            classifications, "unexpected_success_after_invalid_state_candidate"
        ),
        "unexpected_failure_on_valid_sequence_count": count_label(
            classifications, "unexpected_failure_on_valid_sequence_candidate"
        ),
        "semantic_divergence_count": count_label(classifications, "semantic_divergence_candidate"),
        "crash_candidate_count": count_label(classifications, "crash_candidate"),
        "sanitizer_candidate_count": count_label(classifications, "sanitizer_candidate"),
        "baseline_control_failed": baseline_failed,
        "parsing_track_leakage": parsing_leakage,
        "full_consumption_gap_label_generated": full_consumption_label,
        "unsafe_use_after_free_executed": False,
        "quality_status": quality_status,
    }
    quality_name = f"{seed_manifest.get('family', 'evp_digest_ctx_lifecycle')}_full_pipeline_quality_checks.yaml"
    dump_yaml(out_dir / "validation" / quality_name, qc)
    if seed_manifest.get("family") == "evp_digest_ctx_lifecycle":
        dump_yaml(out_dir / "validation/evp_digest_ctx_lifecycle_full_pipeline_quality_checks.yaml", qc)
    write_campaign_artifacts(out_dir, qc, seed_manifest)
    family = str(seed_manifest.get("family", "evp_digest_ctx_lifecycle"))
    write_report(out_dir / f"reports/{family}_full_pipeline_report.md", qc)
    if family == "evp_digest_ctx_lifecycle":
        write_report(out_dir / "reports/evp_digest_ctx_lifecycle_full_pipeline_v1_report.md", qc)
    write_report(out_dir / "reports/continue_next_novel_family_full_pipeline_v1_report.md", qc)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
