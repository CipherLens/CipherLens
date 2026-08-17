from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


RUN_STAGE_SCHEMA = "cipherlens_run_stage_v1"


@dataclass(frozen=True)
class StageSpec:
    id: str
    label: str
    artifact_ids: tuple[str, ...]


STAGE_SPECS: tuple[StageSpec, ...] = (
    StageSpec("family_selection", "Family Selected", ("selected_inputs_status", "selected_patterns")),
    StageSpec("knowledge_retrieval", "Knowledge Retrieval", ("rag_context_status", "rag_context_index", "card_load_report")),
    StageSpec("model_proposal", "Model-assisted Mapping", ("glm_stage_status", "glm_usage_report", "glm_mapping_results")),
    StageSpec("validation", "Deterministic Validation", ("mapping_gate_report", "slot_validation_report", "adapter_validation_report")),
    StageSpec("binding", "Binding Prepared", ("adapter_recipes_glm", "slot_bindings_glm", "slot_bindings")),
    StageSpec("testcase_generation", "Testcase Generated", ("generated_cases_index", "case_matrix", "rendered_cases_manifest")),
    StageSpec("build", "Build", ("compile_stage_status", "compile_run_summary", "compile_report")),
    StageSpec("runtime", "Runtime", ("run_report", "runtime_analyze_report")),
    StageSpec("evaluation", "Multi-dimensional Evaluation", ("oracle_stage_status", "oracle_results", "oracle_classification_summary")),
    StageSpec("result_record", "Candidate / Result Record", ("candidate_queue_delta", "semantic_observation_queue_delta", "safe_reject_baseline_delta")),
    StageSpec("context_exploration", "Context Exploration", ("impactlift_run_summary", "caller_discovery", "candidate_context_pack")),
)


def read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _existing(root: Path, mapping: dict[str, str]) -> list[str]:
    ids: list[str] = []
    for artifact_id, rel_path in mapping.items():
        if (root / rel_path).exists():
            ids.append(artifact_id)
    return ids


def _status_from_raw(value: str) -> str:
    raw = value.lower().strip()
    if raw in {"ready", "pass", "ok", "completed", "complete", "success"}:
        return "completed"
    if raw in {"queued", "pending", "running", "failed", "error", "blocked", "planned", "partial", "not_triggered"}:
        return raw
    if raw.startswith("blocked"):
        return "blocked"
    if raw.startswith("failed") or raw == "fail":
        return "failed"
    if raw.startswith("waiting"):
        return "partial"
    if raw in {"planned_only", "syntax_only", "missing_or_not_found"}:
        return "planned" if raw != "missing_or_not_found" else "partial"
    return raw or "pending"


def _progress_for_status(status: str) -> float | None:
    return {
        "pending": 0.0,
        "queued": 0.0,
        "planned": 0.0,
        "not_triggered": 0.0,
        "running": 0.55,
        "partial": 0.7,
        "blocked": 0.7,
        "failed": 1.0,
        "error": 1.0,
        "completed": 1.0,
    }.get(status)


def _stage(
    spec: StageSpec,
    *,
    status: str,
    artifact_ids: list[str],
    summary: dict[str, Any] | None = None,
    message: str = "",
) -> dict[str, Any]:
    artifact_count = len(artifact_ids)
    return {
        "schema": RUN_STAGE_SCHEMA,
        "id": spec.id,
        "title": spec.label,
        "label": spec.label,
        "status": status,
        "started_at": None,
        "finished_at": None,
        "duration_ms": None,
        "artifact_ids": artifact_ids,
        "artifact_count": artifact_count,
        "detail_available": artifact_count > 0 or bool(summary) or bool(message),
        "progress": _progress_for_status(status),
        "summary": summary or {},
        "message": message,
    }


def mainline_artifact_map(root: Path) -> dict[str, str]:
    return {
        "selected_inputs_status": "selected_inputs/stage_status.yaml",
        "selected_patterns": "selected_inputs/selected_patterns.yaml",
        "target_status": "selected_inputs/target_status.yaml",
        "rag_context_status": "rag_context/stage_status.yaml",
        "rag_context_index": "rag_context/rag_context_index.yaml",
        "glm_stage_status": "glm_slot_filling/stage_status.yaml",
        "glm_usage_report": "glm_slot_filling/glm_usage_report.yaml",
        "glm_mapping_requests": "glm_slot_filling/glm_mapping_requests.yaml",
        "glm_mapping_results": "glm_slot_filling/glm_mapping_results.yaml",
        "adapter_recipes_glm": "adapter_recipes/adapter_recipes_glm.yaml",
        "slot_bindings_glm": "adapter_recipes/slot_bindings_glm.yaml",
        "case_stage_status": "cases/stage_status.yaml",
        "generated_cases_index": "cases/generated_cases_index.yaml",
        "case_matrix": "cases/case_matrix.yaml",
        "compile_stage_status": "compile_run/stage_status.yaml",
        "compile_run_summary": "compile_run/compile_run_summary.yaml",
        "compile_plan": "compile_run/compile_plan.yaml",
        "raw_results": "compile_run/raw_results.yaml",
        "oracle_stage_status": "oracle/stage_status.yaml",
        "oracle_results": "oracle/oracle_results.yaml",
        "oracle_classification_summary": "oracle/oracle_classification_summary.yaml",
        "dispatcher_inputs": "oracle/dispatcher_inputs.yaml",
        "candidate_queue_delta": "oracle/candidate_queue_delta.yaml",
        "semantic_observation_queue_delta": "oracle/semantic_observation_queue_delta.yaml",
        "safe_reject_baseline_delta": "oracle/safe_reject_baseline_delta.yaml",
        "run_manifest": "run_manifest.yaml",
        "quality_report": "quality_report.yaml",
    }


def stage_based_artifact_map(root: Path) -> dict[str, str]:
    return {
        "taxonomy_report": "taxonomy_report.yaml",
        "card_load_report": "card_load_report.yaml",
        "card_contract_validation": "card_contract_validation.yaml",
        "mapping_gate_report": "mapping_gate_report.yaml",
        "campaign_plan": "campaign_plan.yaml",
        "template_pack": "template_pack.yaml",
        "glm_slot_filling_report": "glm_slot_filling_report.yaml",
        "slot_bindings": "slot_bindings.yaml",
        "slot_validation_report": "slot_validation_report.yaml",
        "adapter_validation_report": "adapter_validation_report.yaml",
        "rendered_cases_manifest": "rendered_cases_manifest.yaml",
        "compile_report": "compile_report.yaml",
        "run_report": "run_report.yaml",
        "runtime_analyze_report": "runtime_analyze_report.yaml",
        "oracle_plan": "oracle_plan.yaml",
        "quality_report": "quality_report.yaml",
        "stage_trace": "stage_trace.yaml",
    }


def demo_artifact_map(root: Path) -> dict[str, str]:
    return {
        "proposal": "proposal_loaded.yaml",
        "proposal_validation": "proposal_validation.yaml",
        "rendered_cases_manifest": "render/render_report.yaml",
        "rendered_harness": "render/cmac_lifecycle_replay.c",
        "compile_report": "compile/compile_report.yaml",
        "run_report": "runtime/runtime_report.yaml",
        "runtime_stdout": "runtime/runtime.stdout.log",
        "oracle_results": "oracle/oracle_result.yaml",
        "candidate_queue_delta": "candidate/cmac_lifecycle_candidate.yaml",
        "impactlift_run_summary": "impactlift/run_summary.yaml",
        "caller_discovery": "impactlift/caller_discovery.yaml",
        "candidate_context_pack": "impactlift/candidate_context_pack.yaml",
        "impact_exploration": "impactlift/impact_exploration.yaml",
        "exploitability": "impactlift/exploitability.yaml",
        "security_impact": "impactlift/security_impact.yaml",
        "demo_run_summary": "demo_run_summary.yaml",
    }


def _mainline_summary(root: Path, stage_id: str) -> dict[str, Any]:
    artifacts = mainline_artifact_map(root)
    if stage_id == "family_selection":
        return read_yaml(root / artifacts["selected_inputs_status"])
    if stage_id == "knowledge_retrieval":
        status = read_yaml(root / artifacts["rag_context_status"])
        index = read_yaml(root / artifacts["rag_context_index"])
        return {**status, **{k: v for k, v in index.items() if k in {"context_file_count", "context_files_sample", "family_count"}}}
    if stage_id == "model_proposal":
        status = read_yaml(root / artifacts["glm_stage_status"])
        usage = read_yaml(root / artifacts["glm_usage_report"])
        return {**status, **{k: v for k, v in usage.items() if k not in {"schema"}}}
    if stage_id == "binding":
        recipes = read_yaml(root / artifacts["adapter_recipes_glm"])
        slots = read_yaml(root / artifacts["slot_bindings_glm"])
        return {"adapter_recipe_count": len(recipes.get("items") or []), "slot_binding_count": len(slots.get("items") or [])}
    if stage_id == "testcase_generation":
        return read_yaml(root / artifacts["case_stage_status"]) or read_yaml(root / artifacts["generated_cases_index"])
    if stage_id == "build":
        return read_yaml(root / artifacts["compile_stage_status"]) or read_yaml(root / artifacts["compile_run_summary"])
    if stage_id == "runtime":
        compile_summary = read_yaml(root / artifacts["compile_run_summary"])
        return {
            "execution_mode": compile_summary.get("execution_mode", "unknown"),
            "binary_artifacts_created": compile_summary.get("binary_artifacts_created", False),
            "runtime_harness_executed": False,
        }
    if stage_id == "evaluation":
        return read_yaml(root / artifacts["oracle_stage_status"]) or read_yaml(root / artifacts["oracle_classification_summary"])
    if stage_id == "result_record":
        oracle = read_yaml(root / artifacts["oracle_stage_status"])
        return {
            "candidate_count": oracle.get("new_candidate_count", 0),
            "observation_count": oracle.get("semantic_observation_count", 0),
            "safe_baseline_count": oracle.get("safe_reject_count", 0),
            "needs_review_count": oracle.get("needs_human_triage_count", 0),
        }
    return {}


def _stage_based_summary(root: Path, stage_id: str) -> dict[str, Any]:
    artifacts = stage_based_artifact_map(root)
    if stage_id == "family_selection":
        taxonomy = read_yaml(root / artifacts["taxonomy_report"])
        campaign = read_yaml(root / artifacts["campaign_plan"])
        return {
            "selected_family_count": len(taxonomy.get("selected_families") or []),
            "target_count": len(campaign.get("targets") or []),
            "execution_mode": campaign.get("execution_mode", ""),
        }
    if stage_id == "knowledge_retrieval":
        return read_yaml(root / artifacts["card_load_report"])
    if stage_id == "model_proposal":
        return read_yaml(root / artifacts["glm_slot_filling_report"])
    if stage_id == "validation":
        slot = read_yaml(root / artifacts["slot_validation_report"])
        adapter = read_yaml(root / artifacts["adapter_validation_report"])
        return {**slot, "adapter_validation_passed": adapter.get("adapter_validation_passed", False)}
    if stage_id == "binding":
        slot = read_yaml(root / artifacts["slot_validation_report"])
        return {"usable_bindings": slot.get("usable_bindings", 0), "binding_count": slot.get("binding_count", 0)}
    if stage_id == "testcase_generation":
        return read_yaml(root / artifacts["rendered_cases_manifest"])
    if stage_id == "build":
        return read_yaml(root / artifacts["compile_report"])
    if stage_id == "runtime":
        return read_yaml(root / artifacts["runtime_analyze_report"]) or read_yaml(root / artifacts["run_report"])
    if stage_id == "evaluation":
        return read_yaml(root / artifacts["quality_report"])
    if stage_id == "result_record":
        quality = read_yaml(root / artifacts["quality_report"])
        return {
            "candidate_count": quality.get("candidate_event_count", 0),
            "observation_count": quality.get("semantic_observation_count", 0),
            "cases_run": quality.get("cases_run", 0),
        }
    return {}


def _demo_summary(root: Path, stage_id: str) -> dict[str, Any]:
    artifacts = demo_artifact_map(root)
    oracle_path = root / artifacts["oracle_results"]
    candidate_path = root / artifacts["candidate_queue_delta"]
    impactlift_path = root / artifacts["impactlift_run_summary"]
    oracle = read_yaml(oracle_path)
    candidate = read_yaml(candidate_path)

    if stage_id == "evaluation":
        observed = oracle.get("observed_behavior") if isinstance(oracle.get("observed_behavior"), list) else []
        return {
            "status": oracle.get("status", ""),
            "classification": oracle.get("classification", ""),
            "oracle_type": oracle.get("oracle_type", ""),
            "observation_count": 1 if oracle_path.exists() else 0,
            "observed_behavior_count": len(observed),
        }
    if stage_id == "result_record":
        observed = oracle.get("observed_behavior") if isinstance(oracle.get("observed_behavior"), list) else []
        return {
            "candidate_count": 1 if candidate_path.exists() else 0,
            "observation_count": 1 if oracle_path.exists() else 0,
            "observed_behavior_count": len(observed),
            "candidate_id": candidate.get("candidate_id", ""),
            "classification": candidate.get("classification") or oracle.get("classification", ""),
        }
    if stage_id == "context_exploration":
        impact = read_yaml(impactlift_path)
        callers = impact.get("discovered_callers") if isinstance(impact.get("discovered_callers"), list) else []
        return {
            **impact,
            "candidate_count": 1 if candidate_path.exists() else 0,
            "discovered_caller_count": len(callers),
        }
    return {}


def normalize_stage_based_run_stages(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    artifacts = stage_based_artifact_map(root)
    existing_ids = _existing(root, artifacts)
    stages: list[dict[str, Any]] = []
    for spec in STAGE_SPECS:
        stage_ids = [item for item in existing_ids if item in spec.artifact_ids or item in {
            "taxonomy_report", "card_load_report", "glm_slot_filling_report", "slot_validation_report",
            "adapter_validation_report", "rendered_cases_manifest", "compile_report", "run_report",
            "runtime_analyze_report", "quality_report", "campaign_plan", "slot_bindings",
        }]
        summary = _stage_based_summary(root, spec.id)
        status = "pending"
        message = ""
        if spec.id == "family_selection":
            status = "completed" if (root / artifacts["taxonomy_report"]).exists() else "pending"
            stage_ids = [item for item in existing_ids if item in {"taxonomy_report", "campaign_plan"}]
        elif spec.id == "knowledge_retrieval":
            status = "completed" if (root / artifacts["card_load_report"]).exists() else "pending"
            stage_ids = [item for item in existing_ids if item in {"card_load_report", "card_contract_validation", "mapping_gate_report"}]
        elif spec.id == "model_proposal":
            raw = str(summary.get("status") or "")
            status = "completed" if raw in {"ok", "existing_probe_slots_loaded", "external_manual_slot_bindings_loaded"} else ("partial" if summary else "pending")
            stage_ids = [item for item in existing_ids if item in {"glm_slot_filling_report", "slot_bindings"}]
        elif spec.id == "validation":
            usable = int(summary.get("usable_bindings", 0) or 0)
            status = "completed" if usable > 0 else ("partial" if summary else "pending")
            stage_ids = [item for item in existing_ids if item in {"slot_validation_report", "adapter_validation_report"}]
        elif spec.id == "binding":
            usable = int(summary.get("usable_bindings", 0) or 0)
            status = "completed" if usable > 0 else ("blocked" if (root / artifacts["slot_validation_report"]).exists() else "pending")
            message = "" if usable > 0 else "Runtime smoke is unavailable because no usable runtime binding was produced."
            stage_ids = [item for item in existing_ids if item in {"slot_validation_report", "slot_bindings"}]
        elif spec.id == "testcase_generation":
            raw = str(summary.get("status") or "")
            if raw in {"waiting_for_valid_slot_bindings", "partial"}:
                status = "blocked"
                message = "Testcase rendering was blocked because no usable runtime binding was produced."
            elif summary:
                status = "completed" if int((summary.get("summary") or {}).get("cases_rendered", summary.get("cases_rendered", 0)) or 0) > 0 else "planned"
            stage_ids = [item for item in existing_ids if item in {"rendered_cases_manifest"}]
        elif spec.id == "build":
            raw = str(summary.get("status") or "")
            if raw in {"waiting_for_valid_slot_bindings", "partial"}:
                status = "blocked"
                message = "Build was blocked because no runtime testcase was rendered."
            elif summary:
                counts = summary.get("summary") if isinstance(summary.get("summary"), dict) else summary
                status = "failed" if int(counts.get("compile_failed", 0) or 0) else ("completed" if int(counts.get("compile_success", 0) or 0) else "planned")
            stage_ids = [item for item in existing_ids if item in {"compile_report"}]
        elif spec.id == "runtime":
            if summary.get("runtime_harness_executed"):
                status = "completed"
            elif summary.get("runtime_smoke"):
                status = "blocked"
                message = summary.get("runtime_skip_reason") or summary.get("reason") or "Runtime smoke did not execute."
            elif summary:
                status = "planned"
                message = "Runtime was not executed by syntax check level."
            stage_ids = [item for item in existing_ids if item in {"run_report", "runtime_analyze_report"}]
        elif spec.id == "evaluation":
            status = "completed" if (root / artifacts["quality_report"]).exists() else "pending"
            stage_ids = [item for item in existing_ids if item in {"quality_report", "oracle_plan"}]
        elif spec.id == "result_record":
            status = "completed" if (root / artifacts["quality_report"]).exists() else "pending"
            stage_ids = [item for item in existing_ids if item in {"quality_report"}]
        elif spec.id == "context_exploration":
            result = _stage_based_summary(root, "result_record")
            status = "not_triggered" if (root / artifacts["quality_report"]).exists() else "pending"
            message = "Context exploration is only routed when candidate artifacts are emitted."
            summary = result
            stage_ids = []
        stages.append(_stage(spec, status=status, artifact_ids=stage_ids, summary=summary, message=message))
    return stages


def normalize_mainline_run_stages(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    artifacts = mainline_artifact_map(root)
    stages: list[dict[str, Any]] = []
    for spec in STAGE_SPECS:
        ids = _existing(root, artifacts)
        stage_ids = [item for item in ids if item in spec.artifact_ids]
        summary = _mainline_summary(root, spec.id)
        status = "pending"
        message = ""
        if spec.id == "runtime":
            mode = str(summary.get("execution_mode") or "")
            status = "completed" if summary.get("runtime_harness_executed") else ("planned" if mode == "syntax_only" else "partial")
            message = "Runtime was not executed by syntax-only mainline." if status == "planned" else ""
        elif spec.id == "context_exploration":
            result_summary = _mainline_summary(root, "result_record")
            candidate_count = int(result_summary.get("candidate_count") or 0)
            if (root / artifacts["oracle_stage_status"]).exists() and candidate_count == 0:
                status = "not_triggered"
                message = "No candidate was emitted, so context exploration was not triggered."
                summary = result_summary
            else:
                status = "planned"
                message = "Post-processing runs only when a candidate artifact is routed."
        elif stage_ids:
            raw_status = str(summary.get("status") or summary.get("quality_status") or "ready")
            status = _status_from_raw(raw_status)
        elif spec.id in {"validation"}:
            status = "partial"
            message = "One-click mainline does not emit separate slot validation artifacts."
        elif spec.id in {"result_record"} and (root / artifacts["oracle_stage_status"]).exists():
            status = "completed"
        stages.append(_stage(spec, status=status, artifact_ids=stage_ids, summary=summary, message=message))
    return stages


def normalize_demo_run_stages(root: Path, state_stages: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    root = root.resolve()
    artifacts = demo_artifact_map(root)
    ids = _existing(root, artifacts)
    raw = state_stages or {}
    source_map = {
        "family_selection": ["proposal"],
        "knowledge_retrieval": ["proposal"],
        "model_proposal": ["proposal"],
        "validation": ["proposal_validation"],
        "binding": ["proposal"],
        "testcase_generation": ["rendered_cases_manifest", "rendered_harness"],
        "build": ["compile_report"],
        "runtime": ["run_report"],
        "evaluation": ["oracle_results"],
        "result_record": ["candidate_queue_delta"],
        "context_exploration": ["impactlift_run_summary", "caller_discovery", "candidate_context_pack"],
    }
    legacy_stage_map = {
        "validation": "validation",
        "testcase_generation": "render",
        "build": "compile",
        "runtime": "runtime",
        "evaluation": "oracle",
        "result_record": "candidate",
        "context_exploration": "security_impact",
    }
    stages: list[dict[str, Any]] = []
    for spec in STAGE_SPECS:
        stage_ids = [item for item in ids if item in source_map.get(spec.id, ())]
        legacy = raw.get(legacy_stage_map.get(spec.id, ""), {}) if isinstance(raw, dict) else {}
        status = _status_from_raw(str(legacy.get("status") or "")) if legacy else ("completed" if stage_ids else "pending")
        if spec.id in {"knowledge_retrieval", "model_proposal", "binding"}:
            status = "planned" if stage_ids else status
        summary: dict[str, Any] = _demo_summary(root, spec.id)
        if spec.id == "context_exploration":
            if not (root / artifacts["impactlift_run_summary"]).exists() and not (root / artifacts["candidate_queue_delta"]).exists():
                status = "not_triggered"
                legacy_message = str(legacy.get("message") or "")
                message = legacy_message or "No candidate was emitted, so context exploration was not triggered."
            else:
                message = str(legacy.get("message") or "")
        elif stage_ids:
            summary = summary or read_yaml(root / artifacts[stage_ids[0]])
        stages.append(_stage(spec, status=status, artifact_ids=stage_ids, summary=summary, message=message if spec.id == "context_exploration" else str(legacy.get("message") or "")))
    return stages


def normalize_run_stages(root: Path, *, mode: str, state_stages: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    if mode == "live":
        if (root / "stage_trace.yaml").exists() or (root / "campaign_plan.yaml").exists():
            return normalize_stage_based_run_stages(root)
        return normalize_mainline_run_stages(root)
    return normalize_demo_run_stages(root, state_stages=state_stages)


def summarize_pipeline_coverage(stages: list[dict[str, Any]]) -> dict[str, Any]:
    completed = sum(1 for stage in stages if stage.get("status") == "completed")
    partial = sum(1 for stage in stages if stage.get("status") == "partial")
    blocked = sum(1 for stage in stages if stage.get("status") == "blocked")
    not_executed = sum(1 for stage in stages if stage.get("status") in {"pending", "planned", "not_triggered"})
    executed = sum(1 for stage in stages if stage.get("status") in {"completed", "partial", "failed"})
    failed = sum(1 for stage in stages if stage.get("status") == "failed")
    if failed:
        label = "Failed"
    elif not_executed or partial or blocked:
        label = "Finished with partial coverage"
    else:
        label = "Finished"
    return {
        "executed_stage_count": executed,
        "completed_stage_count": completed,
        "partial_stage_count": partial,
        "blocked_stage_count": blocked,
        "not_executed_stage_count": not_executed,
        "failed_stage_count": failed,
        "pipeline_coverage_label": label,
    }
