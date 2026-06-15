"""Dry-run execution planning for the end-to-end mining orchestrator."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso
from analysis.candidate_queue import build_family_candidate_queue
from analyzer.oracle_event_parser import parse_oracle_events
from runner.family_compile_runner import execute_instrumented_case
from runner.sanitizer_env import lib_dir_for_install, run_env
from mutation.family_profile_loader import family_profile, load_family_profiles
from mutation.generic_mutation_engine import generate_cases
from mutation.mutation_operator_registry import load_operator_registry
from template_maker.family_case_renderer import render_x509_cases_from_render_plan
from template_maker.family_render_plan import build_family_render_plan_from_mutation_matrix


X509_SEED_MANIFEST = Path(
    "artifacts/sprints/x509_family_template_seed_discovery_v1/manifests/verified_x509_seed_manifest.yaml"
)
OPERATOR_REGISTRY = Path("config/mutation_operator_registry.yaml")
FAMILY_PROFILES = Path("config/family_profiles.yaml")
ASAN_OPENSSL_INSTALL = Path("/home/wen/work/install-openssl-3.5.5-asan")
SYSTEM_OPENSSL_BIN = Path("/usr/bin/openssl")


def build_llm_policy(policy_doc: dict[str, Any]) -> dict[str, Any]:
    configured = policy_doc.get("llm_policy", {}) or {}
    return {
        "schema": "llm_slot_filling_policy_v1",
        "generated_at": now_iso(),
        "glm_or_llm_allowed_stage": configured.get("glm_or_llm_allowed_stage", "09_llm_slot_filling"),
        "allowed_output": configured.get("allowed_output", ["slot_bindings.yaml"]),
        "forbidden": configured.get(
            "forbidden_output",
            [
                "complete C harness",
                "adapter_recipes overwrite",
                "normalized_templates overwrite",
                "mapping gate bypass",
            ],
        ),
        "rules": [
            "GLM/LLM can only participate in slot filling.",
            "GLM/LLM can only generate YAML slot_bindings.",
            "GLM/LLM must not generate complete C harnesses.",
            "GLM/LLM must not bypass the mapping gate.",
            "GLM/LLM must not overwrite adapter_recipes or normalized_templates.",
            "All slot_bindings must pass adapter_validate before downstream use.",
        ],
        "adapter_validate_required": True,
    }


def _x509_family(family_state: dict[str, Any]) -> dict[str, Any]:
    for family in family_state.get("families", []) or []:
        if family.get("family") == "x509_parsing":
            return family
    return {}


def build_next_execution_plan(family_state: dict[str, Any]) -> dict[str, Any]:
    x509 = _x509_family(family_state)
    summary = x509.get("summary", {}) or {}
    missing_capability = bool(summary.get("missing_capability"))
    plan = {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "top_ready_family": "x509_parsing",
        "top_ready_stage": "mutation_planner",
        "recommended_next_task": "orchestrator_use_generic_mutation_engine_v1",
        "why": "X.509 DER/PEM seeds are verified and generic mutation engine support is available while ASN.1 and PKCS have external pending gates.",
        "blocked_external_tasks": [
            "external_validation_import_gate_v1",
            "wait_pkcs_app_level_consumption_check",
        ],
        "missing_capabilities": [],
        "status": "ready",
        "blocked_by": [],
    }
    if missing_capability:
        plan["status"] = "missing_capability"
        plan["missing_capabilities"] = [
            {
                "family": "x509_parsing",
                "stage": "mutation_planner",
                "recommended_module_to_implement": "mutation.generic_mutation_engine",
            }
        ]
        plan["blocked_by"] = summary.get("missing_generic_requirements") or ["mutation.generic_mutation_engine"]
    return plan


def build_updated_scheduler_queue(existing_queue: dict[str, Any], next_plan: dict[str, Any]) -> dict[str, Any]:
    tasks = list(existing_queue.get("tasks", []) or [])
    status = "missing_capability" if next_plan.get("status") == "missing_capability" else "ready"
    tasks.insert(
        0,
        {
            "task_name": next_plan["recommended_next_task"],
            "family": next_plan["top_ready_family"],
            "priority": "high",
            "status": status,
            "reason": next_plan["why"],
            "required_inputs": [
                "artifacts/sprints/x509_family_template_seed_discovery_v1/manifests/verified_x509_seed_manifest.yaml",
                "artifacts/sprints/x509_family_template_seed_discovery_v1/plans/x509_template_seed_readiness_plan.yaml",
            ],
            "blocked_by": next_plan.get("blocked_by", []),
            "allowed_to_run_now": status == "ready",
            "owner": "local",
        },
    )
    return {
        "schema": "updated_scheduler_queue_v1",
        "generated_at": now_iso(),
        "source_queue": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([t for t in tasks if t.get("status") == "ready"]),
            "external_pending": len([t for t in tasks if t.get("status") == "external_pending"]),
            "missing_capability": len([t for t in tasks if t.get("status") == "missing_capability"]),
        },
    }


def build_missing_capabilities(next_plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "missing_capabilities_v1",
        "generated_at": now_iso(),
        "missing_capabilities": next_plan.get("missing_capabilities", []),
        "summary": {"total_missing_capabilities": len(next_plan.get("missing_capabilities", []))},
    }


def select_x509_mutation_task(existing_queue: dict[str, Any], next_plan: dict[str, Any]) -> dict[str, Any]:
    source_task = {}
    for task in existing_queue.get("tasks", []) or []:
        if task.get("task_name") == "x509_family_template_seed_discovery_v1":
            source_task = task
            break
    return {
        "schema": "selected_orchestrator_task_v1",
        "generated_at": now_iso(),
        "selected_family": "x509_parsing",
        "selected_stage": "mutation_planner",
        "selected_task": "orchestrator_use_generic_mutation_engine_v1",
        "source_scheduler_task": source_task.get("task_name", ""),
        "source_scheduler_family": source_task.get("family", ""),
        "source_scheduler_status": source_task.get("status", ""),
        "reason": next_plan.get("why", ""),
        "required_inputs": [
            X509_SEED_MANIFEST.as_posix(),
            OPERATOR_REGISTRY.as_posix(),
            FAMILY_PROFILES.as_posix(),
        ],
        "allowed_to_run_now": next_plan.get("status") == "ready",
        "owner": "local",
    }


def _generated_matrix(family: str, seed_manifest: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "generic_mutation_case_matrix_v1",
        "generated_at": now_iso(),
        "family": family,
        "source_seed_manifest": seed_manifest,
        "profile": family,
        "cases": cases,
        "summary": {
            "mutation_case_count": len(cases),
            "strategies": sorted({case["mutation_strategy"] for case in cases}),
            "render_allowed": len([case for case in cases if case.get("render_allowed")]),
            "controls": len(
                [
                    case
                    for case in cases
                    if ((case.get("expected_oracle") or {}).get("malformed_only_control"))
                ]
            ),
        },
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def build_post_mutation_next_plan(cases: list[dict[str, Any]]) -> dict[str, Any]:
    render_ready = len(cases) > 0
    return {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "top_ready_family": "x509_parsing",
        "top_ready_stage": "render_plan",
        "recommended_next_task": "x509_render_plan_v1",
        "why": "Generic mutation planner produced X.509 mutation cases; next local step is render planning, not direct render/compile/run.",
        "blocked_external_tasks": [
            "external_validation_import_gate_v1",
            "wait_pkcs_app_level_consumption_check",
        ],
        "missing_capabilities": [],
        "status": "ready" if render_ready else "blocked",
        "blocked_by": [] if render_ready else ["missing_mutation_cases"],
        "render_ready": render_ready,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
    }


def build_post_mutation_scheduler_queue(existing_queue: dict[str, Any], next_plan: dict[str, Any]) -> dict[str, Any]:
    tasks = list(existing_queue.get("tasks", []) or [])
    tasks.insert(
        0,
        {
            "task_name": next_plan["recommended_next_task"],
            "family": next_plan["top_ready_family"],
            "priority": "high",
            "status": next_plan["status"],
            "reason": next_plan["why"],
            "required_inputs": [
                "artifacts/sprints/orchestrator_use_generic_mutation_engine_v1/mutation/generated_x509_case_matrix.yaml",
                "config/family_profiles.yaml",
                "config/mutation_operator_registry.yaml",
            ],
            "blocked_by": next_plan.get("blocked_by", []),
            "allowed_to_run_now": next_plan.get("status") == "ready",
            "owner": "local",
        },
    )
    return {
        "schema": "updated_scheduler_queue_v1",
        "generated_at": now_iso(),
        "source_queue": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([t for t in tasks if t.get("status") == "ready"]),
            "external_pending": len([t for t in tasks if t.get("status") == "external_pending"]),
            "missing_capability": len([t for t in tasks if t.get("status") == "missing_capability"]),
        },
    }


def execute_generic_x509_mutation_stage(repo_root: Path, out_dir: Path) -> dict[str, Any]:
    registry = load_operator_registry(repo_root / OPERATOR_REGISTRY)
    profiles = load_family_profiles(repo_root / FAMILY_PROFILES)
    profile = family_profile(profiles, "x509_parsing")
    manifest = load_yaml(repo_root / X509_SEED_MANIFEST)
    cases = generate_cases(repo_root, out_dir, "x509_parsing", manifest, profile, registry)
    matrix = _generated_matrix("x509_parsing", X509_SEED_MANIFEST.as_posix(), cases)
    invocation = {
        "schema": "generic_mutation_engine_invocation_v1",
        "generated_at": now_iso(),
        "module": "mutation.generic_mutation_engine",
        "entrypoint": "generate_cases",
        "family": "x509_parsing",
        "repo_root": repo_root.as_posix(),
        "seed_manifest": X509_SEED_MANIFEST.as_posix(),
        "operator_registry": OPERATOR_REGISTRY.as_posix(),
        "family_profiles": FAMILY_PROFILES.as_posix(),
        "family_specific_mutator_required": False,
        "orchestrator_used_generic_engine": True,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "case_count": len(cases),
    }
    trace = {
        "schema": "stage_execution_trace_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "stage": "mutation_planner",
        "owner_module": "mutation.generic_mutation_engine",
        "status": "completed" if cases else "blocked",
        "input_artifacts": [
            X509_SEED_MANIFEST.as_posix(),
            OPERATOR_REGISTRY.as_posix(),
            FAMILY_PROFILES.as_posix(),
        ],
        "output_artifacts": [
            "artifacts/sprints/orchestrator_use_generic_mutation_engine_v1/execution/generic_mutation_engine_invocation.yaml",
            "artifacts/sprints/orchestrator_use_generic_mutation_engine_v1/mutation/generated_x509_case_matrix.yaml",
        ],
        "mutation_case_count": len(cases),
        "mutation_strategies": matrix["summary"]["strategies"],
        "render_ready": len(cases) > 0,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    }
    dump_yaml(out_dir / "execution" / "generic_mutation_engine_invocation.yaml", invocation)
    dump_yaml(out_dir / "execution" / "stage_execution_trace.yaml", trace)
    dump_yaml(out_dir / "mutation" / "generated_x509_case_matrix.yaml", matrix)
    return {"cases": cases, "matrix": matrix, "invocation": invocation, "trace": trace}


def select_x509_render_plan_task(previous_next_plan: dict[str, Any], previous_state: Path) -> dict[str, Any]:
    return {
        "schema": "selected_orchestrator_task_v1",
        "generated_at": now_iso(),
        "selected_family": previous_next_plan.get("top_ready_family", "x509_parsing"),
        "selected_stage": "render_plan",
        "selected_task": "orchestrator_execute_x509_render_plan_v1",
        "previous_state": previous_state.as_posix(),
        "reason": previous_next_plan.get("why", ""),
        "required_inputs": [
            (previous_state / "plans/next_execution_plan.yaml").as_posix(),
            (previous_state / "mutation/generated_x509_case_matrix.yaml").as_posix(),
            FAMILY_PROFILES.as_posix(),
        ],
        "allowed_to_run_now": previous_next_plan.get("top_ready_stage") == "render_plan"
        and previous_next_plan.get("status") == "ready",
        "owner": "local",
    }


def build_post_render_plan_next_plan(render_plan: dict[str, Any]) -> dict[str, Any]:
    summary = render_plan.get("summary", {}) or {}
    ready = bool(summary.get("render_allowed")) and int(summary.get("render_job_count") or 0) > 0
    return {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "top_ready_family": render_plan.get("family", "x509_parsing"),
        "top_ready_stage": "render_cases",
        "recommended_next_task": "x509_render_cases_v1",
        "why": "Render planning completed from the X.509 mutation matrix; next local step is render_cases, not compile/run.",
        "blocked_external_tasks": [
            "external_validation_import_gate_v1",
            "wait_pkcs_app_level_consumption_check",
        ],
        "missing_capabilities": [],
        "status": "ready" if ready else "blocked",
        "blocked_by": [] if ready else ["missing_render_jobs"],
        "render_cases_ready": ready,
        "render_cases_executed": False,
        "harness_generated": False,
        "compile_executed": False,
        "run_executed": False,
    }


def build_post_render_plan_scheduler_queue(existing_queue: dict[str, Any], next_plan: dict[str, Any]) -> dict[str, Any]:
    tasks = list(existing_queue.get("tasks", []) or [])
    tasks.insert(
        0,
        {
            "task_name": next_plan["recommended_next_task"],
            "family": next_plan["top_ready_family"],
            "priority": "high",
            "status": next_plan["status"],
            "reason": next_plan["why"],
            "required_inputs": [
                "artifacts/sprints/orchestrator_execute_x509_render_plan_v1/render_plan/render_plan.yaml"
            ],
            "blocked_by": next_plan.get("blocked_by", []),
            "allowed_to_run_now": next_plan.get("status") == "ready",
            "owner": "local",
        },
    )
    return {
        "schema": "updated_scheduler_queue_v1",
        "generated_at": now_iso(),
        "source_queue": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([t for t in tasks if t.get("status") == "ready"]),
            "external_pending": len([t for t in tasks if t.get("status") == "external_pending"]),
            "missing_capability": len([t for t in tasks if t.get("status") == "missing_capability"]),
        },
    }


def execute_x509_render_plan_stage(repo_root: Path, out_dir: Path, previous_state: Path) -> dict[str, Any]:
    matrix_path = previous_state / "mutation/generated_x509_case_matrix.yaml"
    previous_plan_path = previous_state / "plans/next_execution_plan.yaml"
    profiles_path = repo_root / FAMILY_PROFILES
    matrix = load_yaml(matrix_path)
    previous_plan = load_yaml(previous_plan_path)
    profiles = load_yaml(profiles_path)
    render_plan = build_family_render_plan_from_mutation_matrix(
        matrix,
        source_matrix_path=matrix_path.as_posix(),
        family_profiles=profiles,
    )
    invocation = {
        "schema": "render_plan_invocation_v1",
        "generated_at": now_iso(),
        "module": "template_maker.family_render_plan",
        "entrypoint": "build_family_render_plan_from_mutation_matrix",
        "family": render_plan.get("family", "x509_parsing"),
        "previous_state": previous_state.as_posix(),
        "previous_next_plan": previous_plan_path.as_posix(),
        "mutation_matrix": matrix_path.as_posix(),
        "family_profiles": FAMILY_PROFILES.as_posix(),
        "previous_state_loaded": bool(matrix) and bool(previous_plan),
        "render_plan_executed": True,
        "render_cases_executed": False,
        "harness_generated": False,
        "compile_executed": False,
        "run_executed": False,
        "render_job_count": (render_plan.get("summary") or {}).get("render_job_count", 0),
    }
    trace = {
        "schema": "stage_execution_trace_v1",
        "generated_at": now_iso(),
        "family": render_plan.get("family", "x509_parsing"),
        "stage": "render_plan",
        "owner_module": "template_maker.family_render_plan",
        "status": "completed" if (render_plan.get("summary") or {}).get("render_job_count", 0) else "blocked",
        "input_artifacts": [
            previous_plan_path.as_posix(),
            matrix_path.as_posix(),
            FAMILY_PROFILES.as_posix(),
        ],
        "output_artifacts": [
            "artifacts/sprints/orchestrator_execute_x509_render_plan_v1/execution/render_plan_invocation.yaml",
            "artifacts/sprints/orchestrator_execute_x509_render_plan_v1/render_plan/render_plan.yaml",
        ],
        "input_mutation_case_count": (render_plan.get("summary") or {}).get("input_mutation_case_count", 0),
        "render_job_count": (render_plan.get("summary") or {}).get("render_job_count", 0),
        "next_stage": "render_cases",
        "render_cases_executed": False,
        "harness_generated": False,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    }
    dump_yaml(out_dir / "execution" / "render_plan_invocation.yaml", invocation)
    dump_yaml(out_dir / "execution" / "stage_execution_trace.yaml", trace)
    dump_yaml(out_dir / "render_plan" / "render_plan.yaml", render_plan)
    return {
        "matrix": matrix,
        "previous_plan": previous_plan,
        "profiles": profiles,
        "render_plan": render_plan,
        "invocation": invocation,
        "trace": trace,
    }


def select_x509_render_cases_task(previous_next_plan: dict[str, Any], previous_state: Path) -> dict[str, Any]:
    return {
        "schema": "selected_orchestrator_task_v1",
        "generated_at": now_iso(),
        "selected_family": previous_next_plan.get("top_ready_family", "x509_parsing"),
        "selected_stage": "render_cases",
        "selected_task": "orchestrator_execute_x509_render_cases_v1",
        "previous_state": previous_state.as_posix(),
        "reason": previous_next_plan.get("why", ""),
        "required_inputs": [
            (previous_state / "render_plan/render_plan.yaml").as_posix(),
            (previous_state / "plans/next_execution_plan.yaml").as_posix(),
            FAMILY_PROFILES.as_posix(),
        ],
        "allowed_to_run_now": previous_next_plan.get("top_ready_stage") == "render_cases"
        and previous_next_plan.get("status") == "ready",
        "owner": "local",
    }


def build_post_render_cases_next_plan(case_index: dict[str, Any]) -> dict[str, Any]:
    summary = case_index.get("summary", {}) or {}
    rendered = int(summary.get("rendered") or 0)
    ready = rendered > 0
    return {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "top_ready_family": "x509_parsing",
        "top_ready_stage": "compile_run",
        "recommended_next_task": "x509_compile_run_v1",
        "why": "X.509 render_cases produced harnesses and metadata; next local step is compile_run.",
        "blocked_external_tasks": [
            "external_validation_import_gate_v1",
            "wait_pkcs_app_level_consumption_check",
        ],
        "missing_capabilities": [],
        "status": "ready" if ready else "blocked",
        "blocked_by": [] if ready else ["missing_rendered_cases"],
        "compile_run_ready": ready,
        "rendered_case_count": rendered,
        "compile_executed": False,
        "run_executed": False,
    }


def build_post_render_cases_scheduler_queue(existing_queue: dict[str, Any], next_plan: dict[str, Any]) -> dict[str, Any]:
    tasks = list(existing_queue.get("tasks", []) or [])
    tasks.insert(
        0,
        {
            "task_name": next_plan["recommended_next_task"],
            "family": next_plan["top_ready_family"],
            "priority": "high",
            "status": next_plan["status"],
            "reason": next_plan["why"],
            "required_inputs": [
                "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/case_index/rendered_case_index.yaml",
                "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/rendered_cases/",
            ],
            "blocked_by": next_plan.get("blocked_by", []),
            "allowed_to_run_now": next_plan.get("status") == "ready",
            "owner": "local",
        },
    )
    return {
        "schema": "updated_scheduler_queue_v1",
        "generated_at": now_iso(),
        "source_queue": "artifacts/sprints/scheduler_runtime_loop_v1/queue/scheduler_task_queue.yaml",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([t for t in tasks if t.get("status") == "ready"]),
            "external_pending": len([t for t in tasks if t.get("status") == "external_pending"]),
            "missing_capability": len([t for t in tasks if t.get("status") == "missing_capability"]),
        },
    }


def execute_x509_render_cases_stage(repo_root: Path, out_dir: Path, previous_state: Path) -> dict[str, Any]:
    render_plan_path = previous_state / "render_plan/render_plan.yaml"
    previous_plan_path = previous_state / "plans/next_execution_plan.yaml"
    render_plan = load_yaml(render_plan_path)
    previous_plan = load_yaml(previous_plan_path)
    case_index = render_x509_cases_from_render_plan(render_plan, out_dir)
    summary = case_index.get("summary", {}) or {}
    invocation = {
        "schema": "render_cases_invocation_v1",
        "generated_at": now_iso(),
        "module": "template_maker.family_case_renderer",
        "entrypoint": "render_x509_cases_from_render_plan",
        "family": "x509_parsing",
        "previous_state": previous_state.as_posix(),
        "previous_next_plan": previous_plan_path.as_posix(),
        "render_plan": render_plan_path.as_posix(),
        "previous_state_loaded": bool(render_plan) and bool(previous_plan),
        "render_cases_executed": True,
        "rendered_case_count": int(summary.get("rendered") or 0),
        "harness_generated": int(summary.get("rendered") or 0) > 0,
        "compile_executed": False,
        "run_executed": False,
    }
    trace = {
        "schema": "stage_execution_trace_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "stage": "render_cases",
        "owner_module": "template_maker.family_case_renderer",
        "status": "completed" if int(summary.get("rendered") or 0) > 0 else "blocked",
        "input_artifacts": [
            previous_plan_path.as_posix(),
            render_plan_path.as_posix(),
        ],
        "output_artifacts": [
            "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/execution/render_cases_invocation.yaml",
            "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/case_index/rendered_case_index.yaml",
            "artifacts/sprints/orchestrator_execute_x509_render_cases_v1/rendered_cases/",
        ],
        "render_job_count": int(summary.get("total_planned") or 0),
        "rendered_case_count": int(summary.get("rendered") or 0),
        "next_stage": "compile_run",
        "harness_generated": int(summary.get("rendered") or 0) > 0,
        "compile_executed": False,
        "run_executed": False,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    }
    dump_yaml(out_dir / "execution" / "render_cases_invocation.yaml", invocation)
    dump_yaml(out_dir / "execution" / "stage_execution_trace.yaml", trace)
    return {
        "render_plan": render_plan,
        "previous_plan": previous_plan,
        "case_index": case_index,
        "invocation": invocation,
        "trace": trace,
    }


def select_x509_compile_run_analyze_task(previous_next_plan: dict[str, Any], previous_state: Path) -> dict[str, Any]:
    return {
        "schema": "selected_orchestrator_task_v1",
        "generated_at": now_iso(),
        "selected_family": previous_next_plan.get("top_ready_family", "x509_parsing"),
        "selected_stage": "compile_run_to_oracle_aware_analyze",
        "selected_task": "orchestrator_execute_x509_compile_run_analyze_v1",
        "previous_state": previous_state.as_posix(),
        "reason": previous_next_plan.get("why", ""),
        "required_inputs": [
            (previous_state / "case_index/rendered_case_index.yaml").as_posix(),
            (previous_state / "plans/next_execution_plan.yaml").as_posix(),
        ],
        "allowed_to_run_now": previous_next_plan.get("top_ready_stage") == "compile_run"
        and previous_next_plan.get("status") == "ready",
        "owner": "local",
    }


def _openssl_version(bin_path: Path, install: Path | None = None, lib_dir: Path | None = None) -> tuple[bool, str, str]:
    env = os.environ.copy()
    if install is not None and lib_dir is not None:
        env = run_env(install, lib_dir)
    proc = subprocess.run([bin_path.as_posix(), "version", "-a"], text=True, capture_output=True, env=env)
    output = (proc.stdout + proc.stderr).strip()
    first = output.splitlines()[0] if output else ""
    return proc.returncode == 0, first, output


def resolve_openssl_runtime() -> dict[str, Any]:
    asan_lib_dir = lib_dir_for_install(ASAN_OPENSSL_INSTALL)
    asan_bin = ASAN_OPENSSL_INSTALL / "bin/openssl"
    if asan_bin.exists() and asan_lib_dir.exists():
        ok, first, output = _openssl_version(asan_bin, ASAN_OPENSSL_INSTALL, asan_lib_dir)
        if ok:
            return {
                "openssl_path": asan_bin.as_posix(),
                "openssl_version": first,
                "openssl_install": ASAN_OPENSSL_INSTALL.as_posix(),
                "include_dir": (ASAN_OPENSSL_INSTALL / "include").as_posix(),
                "lib_dir": asan_lib_dir.as_posix(),
                "asan_openssl_available": True,
                "fallback_used": False,
                "fallback_reason": "",
                "version_output": output,
            }
        fallback_reason = output
    else:
        fallback_reason = "ASAN OpenSSL binary or library directory missing"

    ok, first, output = _openssl_version(SYSTEM_OPENSSL_BIN)
    return {
        "openssl_path": SYSTEM_OPENSSL_BIN.as_posix(),
        "openssl_version": first if ok else "unknown",
        "openssl_install": "/usr",
        "include_dir": "/usr/include",
        "lib_dir": "/usr/lib/x86_64-linux-gnu",
        "asan_openssl_available": False,
        "fallback_used": True,
        "fallback_reason": fallback_reason,
        "version_output": output,
    }


def _compile_run_summary(
    rendered_cases: int,
    compile_results: list[dict[str, Any]],
    run_results: list[dict[str, Any]],
    sanitizer_observations: list[dict[str, Any]],
    oracle_events: list[dict[str, Any]],
    openssl_runtime: dict[str, Any],
) -> dict[str, Any]:
    compile_success = len([item for item in compile_results if item.get("compile_status") == "compile_success"])
    run_attempted = len([item for item in run_results if item.get("run_status") != "not_run_compile_failed"])
    normal_exit = len([item for item in run_results if item.get("run_status") == "exited" and item.get("exit_code") == 0])
    nonzero_exit = len([item for item in run_results if item.get("run_status") == "exited" and item.get("exit_code") not in {0, None}])
    crash_signals = len([item for item in run_results if item.get("signal")])
    timeout = len([item for item in run_results if item.get("timeout")])
    asan = len([item for item in sanitizer_observations if "asan" in (item.get("sanitizer_kinds") or [])])
    ubsan = len([item for item in sanitizer_observations if "ubsan" in (item.get("sanitizer_kinds") or [])])
    return {
        "schema": "compile_run_summary_v1",
        "generated_at": now_iso(),
        "rendered_cases": rendered_cases,
        "compile_success": compile_success,
        "compile_failed": len(compile_results) - compile_success,
        "run_attempted": run_attempted,
        "normal_exit": normal_exit,
        "nonzero_exit": nonzero_exit,
        "crash_signals": crash_signals,
        "timeout": timeout,
        "asan_observed": asan,
        "ubsan_observed": ubsan,
        "oracle_events": len(oracle_events),
        "openssl": openssl_runtime,
        "compile_executed": True,
        "run_executed": True,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def _candidate_label_for(run: dict[str, Any], events: list[dict[str, Any]], sanitizer: dict[str, Any]) -> tuple[str, str, bool]:
    if bool(sanitizer.get("sanitizer_observed")):
        return "sanitizer_candidate", "sanitizer output was observed", True
    if run.get("signal"):
        return "crash_candidate", "process terminated with a crash signal", True
    if run.get("timeout"):
        return "needs_triage", "execution timed out", True
    if not events:
        return "oracle_incomplete", "no ORACLE_EVENT records were captured", True
    accepted_true = len([event for event in events if event.get("accepted") in {True, 1, "true"}])
    accepted_false = len([event for event in events if event.get("accepted") in {False, 0, "false"}])
    full_false = len([event for event in events if event.get("full_consumption") in {False, 0, "false"}])
    if accepted_true and full_false:
        return "full_consumption_gap_candidate", "accepted path with full_consumption=false observed", True
    if accepted_true:
        return "normal_accept", "accepted path observed without full-consumption gap", False
    if accepted_false:
        return "normal_reject", "reject path observed", False
    return "needs_triage", "oracle events lacked accepted/reject semantics", True


def _build_x509_analysis(
    run_results: list[dict[str, Any]],
    oracle_events: list[dict[str, Any]],
    sanitizer_observations: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    events_by_case: dict[str, list[dict[str, Any]]] = {}
    for event in oracle_events:
        events_by_case.setdefault(str(event.get("case_id") or ""), []).append(event)
    sanitizer_by_case = {str(item.get("case_id") or ""): item for item in sanitizer_observations}
    cases = []
    labels = []
    for run in run_results:
        case_id = str(run.get("case_id") or "")
        events = events_by_case.get(case_id, [])
        sanitizer = sanitizer_by_case.get(case_id, {})
        label, reason, triage = _candidate_label_for(run, events, sanitizer)
        accepted_true = len([event for event in events if event.get("accepted") in {True, 1, "true"}])
        accepted_false = len([event for event in events if event.get("accepted") in {False, 0, "false"}])
        full_false = len([event for event in events if event.get("full_consumption") in {False, 0, "false"}])
        semantic = label
        if label == "normal_accept":
            semantic = "normal_accept"
        elif label == "normal_reject":
            semantic = "normal_reject"
        cases.append(
            {
                "case_id": case_id,
                "family": run.get("family", "x509_parsing"),
                "target_library": run.get("target_library", "openssl"),
                "mutation_strategy": run.get("mutation_strategy", ""),
                "run_status": run.get("run_status"),
                "exit_code": run.get("exit_code"),
                "signal": run.get("signal", ""),
                "timeout": bool(run.get("timeout")),
                "sanitizer_observed": bool(sanitizer.get("sanitizer_observed")),
                "oracle_event_count": len(events),
                "accepted_true": accepted_true,
                "accepted_false": accepted_false,
                "full_consumption_false": full_false,
                "semantic_observation": semantic,
                "candidate_label": label,
                "triage_required": triage,
                "reason": reason,
            }
        )
        labels.append(
            {
                "case_id": case_id,
                "family": run.get("family", "x509_parsing"),
                "target_library": run.get("target_library", "openssl"),
                "mutation_strategy": run.get("mutation_strategy", ""),
                "candidate_label": label,
                "triage_required": triage,
                "reason": reason,
            }
        )
    allowed = [
        "normal_reject",
        "normal_accept",
        "crash_candidate",
        "sanitizer_candidate",
        "full_consumption_gap_candidate",
        "semantic_divergence_candidate",
        "needs_triage",
        "oracle_incomplete",
        "external_validation_pending",
    ]
    summary = {label: len([item for item in labels if item.get("candidate_label") == label]) for label in allowed}
    summary.update(
        {
            "total_cases": len(cases),
            "oracle_events": len(oracle_events),
            "asan_observed": len(
                [item for item in sanitizer_observations if "asan" in (item.get("sanitizer_kinds") or [])]
            ),
            "ubsan_observed": len(
                [item for item in sanitizer_observations if "ubsan" in (item.get("sanitizer_kinds") or [])]
            ),
        }
    )
    analysis = {
        "schema": "x509_oracle_aware_analysis_v1",
        "generated_at": now_iso(),
        "cases": cases,
        "labels": labels,
        "summary": summary,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }
    family_summary = {
        "schema": "x509_family_summary_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "target_library": "openssl",
        "summary": summary,
        "interpretation": "candidate labels are local oracle classifications only; no vulnerability, CVE, or exploitability claim is made",
    }
    queue = build_family_candidate_queue(
        labels,
        family="x509_parsing",
        source_task="orchestrator_execute_x509_compile_run_analyze_v1",
    )
    return analysis, family_summary, queue


def build_post_compile_analyze_next_plan(queue: dict[str, Any]) -> dict[str, Any]:
    summary = queue.get("summary", {}) or {}
    triage_count = sum(
        int(summary.get(label, 0) or 0)
        for label in (
            "crash_candidate",
            "sanitizer_candidate",
            "full_consumption_gap_candidate",
            "semantic_divergence_candidate",
            "needs_triage",
            "oracle_incomplete",
        )
    )
    return {
        "schema": "next_execution_plan_v1",
        "generated_at": now_iso(),
        "top_ready_family": "x509_parsing",
        "top_ready_stage": "triage" if triage_count else "scheduler_update",
        "recommended_next_task": "x509_candidate_triage_v1" if triage_count else "x509_scheduler_update_v1",
        "why": "compile/run/analyze completed and candidate queue was generated",
        "status": "ready",
        "blocked_by": [],
        "candidate_queue_ready": True,
        "triage_candidate_count": triage_count,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def execute_x509_compile_run_analyze_stage(repo_root: Path, out_dir: Path, previous_state: Path) -> dict[str, Any]:
    case_index_path = previous_state / "case_index/rendered_case_index.yaml"
    previous_plan_path = previous_state / "plans/next_execution_plan.yaml"
    case_index = load_yaml(case_index_path)
    previous_plan = load_yaml(previous_plan_path)
    openssl_runtime = resolve_openssl_runtime()
    install = Path(str(openssl_runtime["openssl_install"]))
    include_dir = Path(str(openssl_runtime["include_dir"]))
    lib_dir = Path(str(openssl_runtime["lib_dir"]))

    compile_results: list[dict[str, Any]] = []
    run_results: list[dict[str, Any]] = []
    oracle_events: list[dict[str, Any]] = []
    sanitizer_observations: list[dict[str, Any]] = []
    for case in case_index.get("cases", []) or []:
        compile_result, run_result, events, sanitizer = execute_instrumented_case(
            case,
            out_dir / "compile_run",
            include_dir,
            lib_dir,
            install,
            10,
            lambda text, _case: parse_oracle_events(text),
        )
        compile_results.append(compile_result)
        run_results.append(run_result)
        oracle_events.extend(events)
        sanitizer_observations.append(sanitizer)

    summary = _compile_run_summary(
        len(case_index.get("cases", []) or []),
        compile_results,
        run_results,
        sanitizer_observations,
        oracle_events,
        openssl_runtime,
    )
    analysis, family_summary, queue = _build_x509_analysis(run_results, oracle_events, sanitizer_observations)
    invocation = {
        "schema": "compile_run_invocation_v1",
        "generated_at": now_iso(),
        "module": "runner.family_compile_runner",
        "entrypoint": "execute_instrumented_case",
        "previous_state": previous_state.as_posix(),
        "case_index": case_index_path.as_posix(),
        "previous_state_loaded": bool(case_index) and bool(previous_plan),
        "compile_run_executed": True,
        "openssl": openssl_runtime,
    }
    analyze_invocation = {
        "schema": "analyze_invocation_v1",
        "generated_at": now_iso(),
        "module": "analyzer.oracle_aware_analyzer",
        "entrypoint": "x509_oracle_aware_analysis",
        "oracle_aware_analyze_executed": True,
        "candidate_queue_generated": True,
        "allowed_candidate_labels": queue.get("allowed_candidate_labels", []),
        "forbidden_labels": queue.get("forbidden_labels", []),
    }
    trace = {
        "schema": "stage_execution_trace_v1",
        "generated_at": now_iso(),
        "family": "x509_parsing",
        "executed_stages": ["compile_run", "oracle_aware_analyze", "candidate_queue"],
        "status": "completed",
        "input_artifacts": [case_index_path.as_posix(), previous_plan_path.as_posix()],
        "output_artifacts": [
            "artifacts/sprints/orchestrator_execute_x509_compile_run_analyze_v1/compile_run/compile_run_summary.yaml",
            "artifacts/sprints/orchestrator_execute_x509_compile_run_analyze_v1/analyze/oracle_aware_analysis.yaml",
            "artifacts/sprints/orchestrator_execute_x509_compile_run_analyze_v1/candidates/x509_candidate_queue.yaml",
        ],
        "next_stage": "triage",
        "compile_executed": True,
        "run_executed": True,
        "oracle_aware_analyze_executed": True,
        "candidate_queue_generated": True,
        "feedback_written": False,
        "knowledge_modified": False,
        "pattern_bank_modified": False,
        "confirmed_vulnerability_claim": False,
    }
    dump_yaml(out_dir / "execution" / "compile_run_invocation.yaml", invocation)
    dump_yaml(out_dir / "execution" / "analyze_invocation.yaml", analyze_invocation)
    dump_yaml(out_dir / "execution" / "stage_execution_trace.yaml", trace)
    dump_yaml(out_dir / "compile_run" / "compile_run_summary.yaml", summary)
    dump_yaml(out_dir / "compile_run" / "run_results.yaml", {"schema": "x509_run_results_v1", "run_results": run_results})
    dump_yaml(
        out_dir / "compile_run" / "compile_results.yaml",
        {"schema": "x509_compile_results_v1", "compile_results": compile_results},
    )
    dump_yaml(
        out_dir / "compile_run" / "oracle_events.yaml",
        {"schema": "x509_oracle_events_v1", "events": oracle_events},
    )
    dump_yaml(
        out_dir / "compile_run" / "sanitizer_observations.yaml",
        {"schema": "x509_sanitizer_observations_v1", "observations": sanitizer_observations},
    )
    dump_yaml(out_dir / "analyze" / "oracle_aware_analysis.yaml", analysis)
    dump_yaml(out_dir / "analyze" / "family_summary.yaml", family_summary)
    dump_yaml(out_dir / "candidates" / "x509_candidate_queue.yaml", queue)
    return {
        "case_index": case_index,
        "previous_plan": previous_plan,
        "compile_results": compile_results,
        "run_results": run_results,
        "oracle_events": oracle_events,
        "sanitizer_observations": sanitizer_observations,
        "compile_run_summary": summary,
        "analysis": analysis,
        "family_summary": family_summary,
        "candidate_queue": queue,
        "invocation": invocation,
        "analyze_invocation": analyze_invocation,
        "trace": trace,
    }
