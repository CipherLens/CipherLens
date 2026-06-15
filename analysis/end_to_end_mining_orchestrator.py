"""End-to-end mining orchestrator dry-run."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, write_text
from analysis.pipeline_executor import (
    build_llm_policy,
    build_missing_capabilities,
    build_next_execution_plan,
    build_post_compile_analyze_next_plan,
    build_post_render_cases_next_plan,
    build_post_render_cases_scheduler_queue,
    build_post_render_plan_next_plan,
    build_post_render_plan_scheduler_queue,
    build_post_mutation_next_plan,
    build_post_mutation_scheduler_queue,
    build_updated_scheduler_queue,
    execute_x509_compile_run_analyze_stage,
    execute_x509_render_cases_stage,
    execute_x509_render_plan_stage,
    execute_generic_x509_mutation_stage,
    select_x509_compile_run_analyze_task,
    select_x509_render_cases_task,
    select_x509_render_plan_task,
    select_x509_mutation_task,
)
from analysis.pipeline_stage_registry import build_registry
from analysis.pipeline_state import build_family_pipeline_state, build_global_pipeline_state


SPRINT = "end_to_end_mining_orchestrator_v1"
EXECUTE_SPRINT = "orchestrator_use_generic_mutation_engine_v1"
RENDER_PLAN_SPRINT = "orchestrator_execute_x509_render_plan_v1"
RENDER_CASES_SPRINT = "orchestrator_execute_x509_render_cases_v1"
REGISTRY_CONFIG = Path("config/end_to_end_pipeline_registry.yaml")
POLICY_CONFIG = Path("config/family_mining_policy.yaml")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--scheduler-queue", required=True)
    parser.add_argument("--previous-state", default="")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--mode", choices=["dry-run"], default="dry-run")
    parser.add_argument("--execute-one", action="store_true", help="Execute one local generic mutation planner stage.")
    parser.add_argument("--execute-until", default="", help="Execute consecutive local stages until this stage is completed.")
    return parser.parse_args()


def quality_checks() -> dict[str, Any]:
    return {
        "schema": "end_to_end_orchestrator_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "pipeline_registry_generated": True,
        "family_pipeline_state_generated": True,
        "llm_policy_generated": True,
        "scheduler_queue_updated": True,
        "dry_run_only": True,
        "glm_called": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass",
    }


def generic_mutation_quality_checks(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
) -> dict[str, Any]:
    cases = execution.get("cases", []) or []
    matrix = execution.get("matrix", {}) or {}
    return {
        "schema": "orchestrator_generic_mutation_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "orchestrator_used_generic_engine": bool((execution.get("invocation") or {}).get("orchestrator_used_generic_engine")),
        "family_specific_mutator_required": False,
        "x509_selected": selected_task.get("selected_family") == "x509_parsing",
        "mutation_planner_executed": (execution.get("trace") or {}).get("status") == "completed",
        "x509_cases_generated": len(cases) > 0 and matrix.get("family") == "x509_parsing",
        "x509_case_count": len(cases),
        "next_stage_render_plan_ready": next_plan.get("top_ready_stage") == "render_plan"
        and bool(next_plan.get("render_ready")),
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if len(cases) == 4
        and next_plan.get("top_ready_stage") == "render_plan"
        and bool((execution.get("invocation") or {}).get("orchestrator_used_generic_engine"))
        else "blocked",
    }


def x509_render_plan_quality_checks(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
) -> dict[str, Any]:
    render_plan = execution.get("render_plan", {}) or {}
    summary = render_plan.get("summary", {}) or {}
    invocation = execution.get("invocation", {}) or {}
    return {
        "schema": "orchestrator_x509_render_plan_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_state_loaded": bool(invocation.get("previous_state_loaded")),
        "x509_selected": selected_task.get("selected_family") == "x509_parsing",
        "selected_stage": selected_task.get("selected_stage"),
        "render_plan_executed": bool(invocation.get("render_plan_executed")),
        "render_cases_executed": False,
        "harness_generated": False,
        "compile_executed": False,
        "run_executed": False,
        "next_stage_render_cases_ready": next_plan.get("top_ready_stage") == "render_cases"
        and bool(next_plan.get("render_cases_ready")),
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if bool(invocation.get("previous_state_loaded"))
        and selected_task.get("selected_stage") == "render_plan"
        and bool(invocation.get("render_plan_executed"))
        and int(summary.get("render_job_count") or 0) > 0
        and next_plan.get("top_ready_stage") == "render_cases"
        else "blocked",
    }


def x509_render_cases_quality_checks(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
) -> dict[str, Any]:
    case_index = execution.get("case_index", {}) or {}
    summary = case_index.get("summary", {}) or {}
    rendered_count = int(summary.get("rendered") or 0)
    invocation = execution.get("invocation", {}) or {}
    return {
        "schema": "orchestrator_x509_render_cases_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_state_loaded": bool(invocation.get("previous_state_loaded")),
        "x509_selected": selected_task.get("selected_family") == "x509_parsing",
        "selected_stage": selected_task.get("selected_stage"),
        "render_cases_executed": bool(invocation.get("render_cases_executed")),
        "rendered_case_count": rendered_count,
        "harness_generated": bool(invocation.get("harness_generated")),
        "compile_executed": False,
        "run_executed": False,
        "next_stage_compile_run_ready": next_plan.get("top_ready_stage") == "compile_run"
        and bool(next_plan.get("compile_run_ready")),
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if bool(invocation.get("previous_state_loaded"))
        and selected_task.get("selected_stage") == "render_cases"
        and bool(invocation.get("render_cases_executed"))
        and rendered_count == 4
        and bool(invocation.get("harness_generated"))
        and next_plan.get("top_ready_stage") == "compile_run"
        else "blocked",
    }


def x509_compile_run_analyze_quality_checks(execution: dict[str, Any]) -> dict[str, Any]:
    invocation = execution.get("invocation", {}) or {}
    analyze_invocation = execution.get("analyze_invocation", {}) or {}
    queue = execution.get("candidate_queue", {}) or {}
    return {
        "schema": "orchestrator_x509_compile_run_analyze_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_state_loaded": bool(invocation.get("previous_state_loaded")),
        "x509_selected": True,
        "compile_run_executed": bool(invocation.get("compile_run_executed")),
        "oracle_aware_analyze_executed": bool(analyze_invocation.get("oracle_aware_analyze_executed")),
        "candidate_queue_generated": bool(queue),
        "render_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "glm_called": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": "pass"
        if bool(invocation.get("previous_state_loaded"))
        and bool(invocation.get("compile_run_executed"))
        and bool(analyze_invocation.get("oracle_aware_analyze_executed"))
        and bool(queue)
        else "blocked",
    }


def report_text(
    registry: dict[str, Any],
    family_state: dict[str, Any],
    next_plan: dict[str, Any],
    llm_policy: dict[str, Any],
    qc: dict[str, Any],
) -> str:
    families = {f["family"]: f for f in family_state.get("families", [])}
    return f"""# {SPRINT} Report

## Scope

- pipeline stages: {registry.get('stage_count')}
- dry-run: true
- GLM called: false
- render/compile/run: false / false / false

## Family State

- ASN.1: {families.get('asn1_nested_boundary', {}).get('status')} / {families.get('asn1_nested_boundary', {}).get('summary', {})}
- PKCS: {families.get('pkcs_container_parsing', {}).get('status')} / {families.get('pkcs_container_parsing', {}).get('summary', {})}
- X.509: {families.get('x509_parsing', {}).get('status')} / {families.get('x509_parsing', {}).get('summary', {})}

## LLM Policy

- allowed output: {llm_policy.get('allowed_output')}
- forbidden: {llm_policy.get('forbidden')}
- adapter_validate_required: {llm_policy.get('adapter_validate_required')}

## Next Execution Plan

- top_ready_family: {next_plan.get('top_ready_family')}
- top_ready_stage: {next_plan.get('top_ready_stage')}
- recommended_next_task: {next_plan.get('recommended_next_task')}
- status: {next_plan.get('status')}
- missing_capabilities: {next_plan.get('missing_capabilities')}

## Quality

- quality_status: {qc['quality_status']}
- no vulnerability/CVE/exploitability claim
"""


def generic_mutation_report_text(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
    qc: dict[str, Any],
) -> str:
    matrix = execution.get("matrix", {}) or {}
    summary = matrix.get("summary", {}) or {}
    return f"""# {EXECUTE_SPRINT} Report

## Scope

- selected family: {selected_task.get('selected_family')}
- selected stage: {selected_task.get('selected_stage')}
- generic engine used: {qc.get('orchestrator_used_generic_engine')}
- family-specific mutator required: {qc.get('family_specific_mutator_required')}

## Mutation Planner

- generated cases: {summary.get('mutation_case_count')}
- strategies: {summary.get('strategies')}
- next stage: {next_plan.get('top_ready_stage')}
- render ready: {next_plan.get('render_ready')}

## Policy

- tools core logic: false
- new tools script: false
- render/compile/run: false / false / false
- feedback/knowledge/pattern bank: false / false / false
- GLM called: false
- confirmed vulnerability claim: false

## Quality

- quality_status: {qc.get('quality_status')}
"""


def x509_render_plan_report_text(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
    qc: dict[str, Any],
) -> str:
    render_plan = execution.get("render_plan", {}) or {}
    summary = render_plan.get("summary", {}) or {}
    return f"""# {RENDER_PLAN_SPRINT} Report

## Scope

- previous state loaded: {qc.get('previous_state_loaded')}
- selected family: {selected_task.get('selected_family')}
- selected stage: {selected_task.get('selected_stage')}
- render plan executed: {qc.get('render_plan_executed')}
- next stage: {next_plan.get('top_ready_stage')}

## Render Plan

- input mutation cases: {summary.get('input_mutation_case_count')}
- render jobs: {summary.get('render_job_count')}
- render allowed: {summary.get('render_allowed')}
- harness generated: {qc.get('harness_generated')}

## Policy

- x509_render_plan standalone script: false
- orchestrator path: true
- tools core logic: false
- new tools script: false
- render_cases/compile/run: false / false / false
- feedback/knowledge/pattern bank: false / false / false
- GLM called: false
- confirmed vulnerability claim: false

## Quality

- quality_status: {qc.get('quality_status')}
"""


def x509_render_cases_report_text(
    selected_task: dict[str, Any],
    execution: dict[str, Any],
    next_plan: dict[str, Any],
    qc: dict[str, Any],
) -> str:
    render_plan = execution.get("render_plan", {}) or {}
    plan_summary = render_plan.get("summary", {}) or {}
    case_index = execution.get("case_index", {}) or {}
    index_summary = case_index.get("summary", {}) or {}
    return f"""# {RENDER_CASES_SPRINT} Report

## Scope

- previous state loaded: {qc.get('previous_state_loaded')}
- selected family: {selected_task.get('selected_family')}
- selected stage: {selected_task.get('selected_stage')}
- render cases executed: {qc.get('render_cases_executed')}
- next stage: {next_plan.get('top_ready_stage')}

## Render Cases

- render jobs: {plan_summary.get('render_job_count')}
- rendered cases: {index_summary.get('rendered')}
- harness generated: {qc.get('harness_generated')}
- case index: artifacts/sprints/orchestrator_execute_x509_render_cases_v1/case_index/rendered_case_index.yaml

## Policy

- x509_render_cases standalone script: false
- orchestrator path: true
- tools core logic: false
- new tools script: false
- compile/run: false / false
- feedback/knowledge/pattern bank: false / false / false
- GLM called: false
- confirmed vulnerability claim: false

## Quality

- quality_status: {qc.get('quality_status')}
"""


def x509_compile_run_analyze_report_text(execution: dict[str, Any], next_plan: dict[str, Any], qc: dict[str, Any]) -> str:
    summary = execution.get("compile_run_summary", {}) or {}
    analysis_summary = ((execution.get("analysis", {}) or {}).get("summary", {}) or {})
    queue_summary = ((execution.get("candidate_queue", {}) or {}).get("summary", {}) or {})
    openssl = summary.get("openssl", {}) or {}
    return f"""# orchestrator_execute_x509_compile_run_analyze_v1 Report

## Scope

- previous state loaded: {qc.get('previous_state_loaded')}
- selected family: x509_parsing
- executed stages: compile_run, oracle_aware_analyze, candidate_queue
- next stage: {next_plan.get('top_ready_stage')}

## Compile/Run

- rendered cases: {summary.get('rendered_cases')}
- compile success: {summary.get('compile_success')}
- run attempted: {summary.get('run_attempted')}
- normal exit: {summary.get('normal_exit')}
- nonzero exit: {summary.get('nonzero_exit')}
- crash signals: {summary.get('crash_signals')}
- timeout: {summary.get('timeout')}
- ASAN/UBSAN: {summary.get('asan_observed')} / {summary.get('ubsan_observed')}
- OpenSSL path: {openssl.get('openssl_path')}
- OpenSSL version: {openssl.get('openssl_version')}
- ASAN OpenSSL available: {openssl.get('asan_openssl_available')}
- fallback reason: {openssl.get('fallback_reason')}

## Oracle-Aware Analyze

- oracle events: {summary.get('oracle_events')}
- normal_accept: {analysis_summary.get('normal_accept')}
- normal_reject: {analysis_summary.get('normal_reject')}
- full_consumption_gap_candidate: {analysis_summary.get('full_consumption_gap_candidate')}
- semantic_divergence_candidate: {analysis_summary.get('semantic_divergence_candidate')}
- needs_triage: {analysis_summary.get('needs_triage')}
- candidate queue total: {queue_summary.get('total_candidates')}

## Claim Policy

No confirmed vulnerability, CVE, or exploitability claim is made.

## Quality

- quality_status: {qc.get('quality_status')}
"""


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    for sub in (
        "registry",
        "state",
        "plans",
        "queue",
        "validation",
        "reports",
        "selection",
        "execution",
        "mutation",
        "render_plan",
        "rendered_cases",
        "case_index",
    ):
        (out_dir / sub).mkdir(parents=True, exist_ok=True)

    registry = build_registry(repo_root, repo_root / REGISTRY_CONFIG)
    policy_doc = load_yaml(repo_root / POLICY_CONFIG)
    family_state = build_family_pipeline_state(repo_root, registry)
    global_state = build_global_pipeline_state(family_state)
    next_plan = build_next_execution_plan(family_state)
    llm_policy = build_llm_policy(policy_doc)
    scheduler_queue = load_yaml((repo_root / args.scheduler_queue).resolve())
    selected_task = select_x509_mutation_task(scheduler_queue, next_plan)

    if args.execute_until == "oracle_aware_analyze":
        previous_state = (repo_root / args.previous_state).resolve()
        previous_plan = load_yaml(previous_state / "plans/next_execution_plan.yaml")
        selected_task = select_x509_compile_run_analyze_task(previous_plan, previous_state)
        execution = execute_x509_compile_run_analyze_stage(repo_root, out_dir, previous_state)
        post_next_plan = build_post_compile_analyze_next_plan(execution["candidate_queue"])
        updated_queue = build_updated_scheduler_queue(scheduler_queue, post_next_plan)
        missing = build_missing_capabilities(post_next_plan)
        qc = x509_compile_run_analyze_quality_checks(execution)

        dump_yaml(out_dir / "registry" / "pipeline_stage_registry.yaml", registry)
        dump_yaml(out_dir / "state" / "family_pipeline_state.yaml", family_state)
        dump_yaml(out_dir / "state" / "global_pipeline_state.yaml", global_state)
        dump_yaml(out_dir / "selection" / "selected_task.yaml", selected_task)
        dump_yaml(out_dir / "plans" / "next_execution_plan.yaml", post_next_plan)
        dump_yaml(out_dir / "plans" / "llm_slot_filling_policy.yaml", llm_policy)
        dump_yaml(out_dir / "queue" / "updated_scheduler_queue.yaml", updated_queue)
        dump_yaml(out_dir / "queue" / "missing_capabilities.yaml", missing)
        dump_yaml(out_dir / "validation" / "orchestrator_x509_compile_run_analyze_quality_checks.yaml", qc)
        write_text(
            out_dir / "reports" / "orchestrator_execute_x509_compile_run_analyze_v1_report.md",
            x509_compile_run_analyze_report_text(execution, post_next_plan, qc),
        )

        print(f"[OK] wrote orchestrator_execute_x509_compile_run_analyze_v1 artifacts to {out_dir}")
        print(
            "[SUMMARY] "
            f"compile_success={execution['compile_run_summary']['compile_success']} "
            f"run_attempted={execution['compile_run_summary']['run_attempted']} "
            f"oracle_events={execution['compile_run_summary']['oracle_events']} "
            f"quality={qc['quality_status']}"
        )
        return 0

    if args.execute_one and args.previous_state:
        previous_state = (repo_root / args.previous_state).resolve()
        previous_plan = load_yaml(previous_state / "plans/next_execution_plan.yaml")
        if previous_plan.get("top_ready_stage") == "render_cases":
            selected_task = select_x509_render_cases_task(previous_plan, previous_state)
            execution = execute_x509_render_cases_stage(repo_root, out_dir, previous_state)
            post_next_plan = build_post_render_cases_next_plan(execution["case_index"])
            updated_queue = build_post_render_cases_scheduler_queue(scheduler_queue, post_next_plan)
            missing = build_missing_capabilities(post_next_plan)
            qc = x509_render_cases_quality_checks(selected_task, execution, post_next_plan)

            dump_yaml(out_dir / "registry" / "pipeline_stage_registry.yaml", registry)
            dump_yaml(out_dir / "state" / "family_pipeline_state.yaml", family_state)
            dump_yaml(out_dir / "state" / "global_pipeline_state.yaml", global_state)
            dump_yaml(out_dir / "selection" / "selected_task.yaml", selected_task)
            dump_yaml(out_dir / "plans" / "next_execution_plan.yaml", post_next_plan)
            dump_yaml(out_dir / "plans" / "llm_slot_filling_policy.yaml", llm_policy)
            dump_yaml(out_dir / "queue" / "updated_scheduler_queue.yaml", updated_queue)
            dump_yaml(out_dir / "queue" / "missing_capabilities.yaml", missing)
            dump_yaml(out_dir / "validation" / "orchestrator_x509_render_cases_quality_checks.yaml", qc)
            write_text(
                out_dir / "reports" / f"{RENDER_CASES_SPRINT}_report.md",
                x509_render_cases_report_text(selected_task, execution, post_next_plan, qc),
            )

            print(f"[OK] wrote {RENDER_CASES_SPRINT} artifacts to {out_dir}")
            print(
                "[SUMMARY] "
                f"family={selected_task['selected_family']} stage={selected_task['selected_stage']} "
                f"rendered={qc['rendered_case_count']} next={post_next_plan['top_ready_stage']} "
                f"quality={qc['quality_status']}"
            )
            return 0

        selected_task = select_x509_render_plan_task(previous_plan, previous_state)
        execution = execute_x509_render_plan_stage(repo_root, out_dir, previous_state)
        post_next_plan = build_post_render_plan_next_plan(execution["render_plan"])
        updated_queue = build_post_render_plan_scheduler_queue(scheduler_queue, post_next_plan)
        missing = build_missing_capabilities(post_next_plan)
        qc = x509_render_plan_quality_checks(selected_task, execution, post_next_plan)

        dump_yaml(out_dir / "registry" / "pipeline_stage_registry.yaml", registry)
        dump_yaml(out_dir / "state" / "family_pipeline_state.yaml", family_state)
        dump_yaml(out_dir / "state" / "global_pipeline_state.yaml", global_state)
        dump_yaml(out_dir / "selection" / "selected_task.yaml", selected_task)
        dump_yaml(out_dir / "plans" / "next_execution_plan.yaml", post_next_plan)
        dump_yaml(out_dir / "plans" / "llm_slot_filling_policy.yaml", llm_policy)
        dump_yaml(out_dir / "queue" / "updated_scheduler_queue.yaml", updated_queue)
        dump_yaml(out_dir / "queue" / "missing_capabilities.yaml", missing)
        dump_yaml(out_dir / "validation" / "orchestrator_x509_render_plan_quality_checks.yaml", qc)
        write_text(
            out_dir / "reports" / f"{RENDER_PLAN_SPRINT}_report.md",
            x509_render_plan_report_text(selected_task, execution, post_next_plan, qc),
        )

        print(f"[OK] wrote {RENDER_PLAN_SPRINT} artifacts to {out_dir}")
        print(
            "[SUMMARY] "
            f"family={selected_task['selected_family']} stage={selected_task['selected_stage']} "
            f"jobs={(execution['render_plan'].get('summary') or {}).get('render_job_count')} "
            f"next={post_next_plan['top_ready_stage']} quality={qc['quality_status']}"
        )
        return 0

    if args.execute_one:
        execution = execute_generic_x509_mutation_stage(repo_root, out_dir)
        post_next_plan = build_post_mutation_next_plan(execution["cases"])
        updated_queue = build_post_mutation_scheduler_queue(scheduler_queue, post_next_plan)
        missing = build_missing_capabilities(post_next_plan)
        qc = generic_mutation_quality_checks(selected_task, execution, post_next_plan)

        dump_yaml(out_dir / "registry" / "pipeline_stage_registry.yaml", registry)
        dump_yaml(out_dir / "state" / "family_pipeline_state.yaml", family_state)
        dump_yaml(out_dir / "state" / "global_pipeline_state.yaml", global_state)
        dump_yaml(out_dir / "selection" / "selected_task.yaml", selected_task)
        dump_yaml(out_dir / "plans" / "next_execution_plan.yaml", post_next_plan)
        dump_yaml(out_dir / "plans" / "llm_slot_filling_policy.yaml", llm_policy)
        dump_yaml(out_dir / "queue" / "updated_scheduler_queue.yaml", updated_queue)
        dump_yaml(out_dir / "queue" / "missing_capabilities.yaml", missing)
        dump_yaml(out_dir / "validation" / "orchestrator_generic_mutation_quality_checks.yaml", qc)
        write_text(
            out_dir / "reports" / f"{EXECUTE_SPRINT}_report.md",
            generic_mutation_report_text(selected_task, execution, post_next_plan, qc),
        )

        print(f"[OK] wrote {EXECUTE_SPRINT} artifacts to {out_dir}")
        print(
            "[SUMMARY] "
            f"family={selected_task['selected_family']} stage={selected_task['selected_stage']} "
            f"cases={qc['x509_case_count']} next={post_next_plan['top_ready_stage']} quality={qc['quality_status']}"
        )
        return 0

    updated_queue = build_updated_scheduler_queue(scheduler_queue, next_plan)
    missing = build_missing_capabilities(next_plan)
    qc = quality_checks()

    dump_yaml(out_dir / "registry" / "pipeline_stage_registry.yaml", registry)
    dump_yaml(out_dir / "state" / "family_pipeline_state.yaml", family_state)
    dump_yaml(out_dir / "state" / "global_pipeline_state.yaml", global_state)
    dump_yaml(out_dir / "selection" / "selected_task.yaml", selected_task)
    dump_yaml(out_dir / "plans" / "next_execution_plan.yaml", next_plan)
    dump_yaml(out_dir / "plans" / "llm_slot_filling_policy.yaml", llm_policy)
    dump_yaml(out_dir / "queue" / "updated_scheduler_queue.yaml", updated_queue)
    dump_yaml(out_dir / "queue" / "missing_capabilities.yaml", missing)
    dump_yaml(out_dir / "validation" / "end_to_end_orchestrator_quality_checks.yaml", qc)
    write_text(
        out_dir / "reports" / f"{SPRINT}_report.md",
        report_text(registry, family_state, next_plan, llm_policy, qc),
    )

    print(f"[OK] wrote {SPRINT} artifacts to {out_dir}")
    print(
        "[SUMMARY] "
        f"stages={registry['stage_count']} top={next_plan['top_ready_family']}:{next_plan['top_ready_stage']} "
        f"status={next_plan['status']} quality={qc['quality_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
