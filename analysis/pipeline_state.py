"""Build dry-run family pipeline state from existing sprint artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import load_yaml, now_iso
from analysis.pipeline_records import family_state_record, stage_record


def _stage(template: dict[str, Any], status: str, blocked_by: list[str], allowed: bool, notes: list[str]) -> dict[str, Any]:
    return stage_record(
        str(template["stage_id"]),
        str(template["stage_name"]),
        str(template["owner_module"]),
        list(template.get("input_artifacts", [])),
        list(template.get("output_artifacts", [])),
        status,
        blocked_by,
        bool(template.get("uses_llm")),
        str(template.get("llm_allowed_output", "")),
        allowed,
        notes,
    )


def _templates(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f"{s['stage_id']}_{s['stage_name']}": s for s in registry.get("stages", [])}


def x509_state(repo_root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    t = _templates(registry)
    seed_plan = load_yaml(
        repo_root / "artifacts/sprints/x509_family_template_seed_discovery_v1/plans/x509_template_seed_readiness_plan.yaml"
    )
    can_mutate = bool(seed_plan.get("can_start_valid_prefix_mutation"))
    generic_requirements = [
        "mutation/generic_mutation_engine.py",
        "mutation/mutation_operator_registry.py",
        "mutation/family_profile_loader.py",
        "config/mutation_operator_registry.yaml",
        "config/family_profiles.yaml",
    ]
    missing_generic_requirements = [path for path in generic_requirements if not (repo_root / path).exists()]
    missing_capability = bool(missing_generic_requirements)
    stages = []
    completed_names = {
        "01_ingestion",
        "02_family_correction",
        "03_rag_lookup",
        "04_mapping_gate",
        "05_family_template_recipe",
        "06_family_template_generalization",
        "07_adapter_recipe",
        "08_slot_filling_plan",
        "09_llm_slot_filling",
        "10_adapter_validate",
    }
    for key, template in t.items():
        if key in completed_names:
            stages.append(_stage(template, "ready_or_available_from_prior_artifacts", [], False, ["prior sprint artifacts exist or can be reused"]))
        elif key == "11_mutation_planner":
            status = "missing_capability" if missing_capability else "ready"
            stages.append(
                _stage(
                    template,
                    status,
                    missing_generic_requirements,
                    can_mutate and not missing_capability,
                    [
                        "DER/PEM verified X.509 seeds are ready",
                        "mutation planner uses mutation.generic_mutation_engine",
                        "family-specific mutator is not required",
                    ],
                )
            )
        else:
            stages.append(_stage(template, "blocked", ["11_mutation_planner"], False, ["downstream of X.509 mutation planner"]))
    return family_state_record(
        "x509_parsing",
        "ready_for_mutation_planner" if can_mutate and not missing_capability else "missing_capability",
        stages,
        {
            "seed_discovery_done": bool(seed_plan),
            "der_seed_ready": bool(seed_plan.get("verified_der_seed_ready")),
            "pem_seed_ready": bool(seed_plan.get("verified_pem_seed_ready")),
            "next_stage": "mutation_planner",
            "recommended_next_task": "orchestrator_use_generic_mutation_engine_v1",
            "missing_capability": missing_capability,
            "recommended_module_to_implement": "mutation.generic_mutation_engine" if missing_capability else "",
            "family_specific_mutator_required": False,
            "generic_engine_requirements": generic_requirements,
            "missing_generic_requirements": missing_generic_requirements,
        },
    )


def asn1_state(repo_root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    t = _templates(registry)
    candidate = load_yaml(repo_root / "artifacts/sprints/family_loop_closure_report_v1/candidate_status/candidate_status.yaml")
    candidate_block = candidate.get("candidates") or {}
    pending = int(candidate_block.get("external_validation_pending") or 0)
    if candidate_block.get("status") == "external_validation_pending":
        pending = int(candidate_block.get("total") or pending)
    stages = []
    for key, template in t.items():
        if key in {"16_triage", "17_runtime_feedback", "18_scheduler_update"}:
            stages.append(_stage(template, "external_pending", ["teammate_external_validation"], False, ["loop closed; candidates await external validation import gate"]))
        else:
            stages.append(_stage(template, "complete_or_available", [], False, ["ASN.1 loop closed in prior sprint"]))
    return family_state_record(
        "asn1_nested_boundary",
        "external_pending",
        stages,
        {
            "loop_closed": True,
            "candidates": "external_validation_pending" if pending else "none",
            "external_validation_pending": pending,
            "next_gate": "external_validation_import_gate_v1",
        },
    )


def pkcs_state(repo_root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    t = _templates(registry)
    analysis = load_yaml(repo_root / "artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/analyze/oracle_aware_analysis.yaml")
    triage = load_yaml(repo_root / "artifacts/sprints/pkcs_candidate_external_validation_v1/triage/pkcs_candidate_triage.yaml")
    full = int((analysis.get("summary") or {}).get("full_consumption_gap_candidate", 0) or 0)
    caller_must = int((triage.get("summary") or {}).get("caller_must_check_consumption", 0) or 0)
    stages = []
    for key, template in t.items():
        if key in {"16_triage", "17_runtime_feedback", "18_scheduler_update"}:
            stages.append(_stage(template, "external_pending", ["pkcs_app_level_consumption_check_v1"], False, ["app-level caller behavior assigned to teammate"]))
        else:
            stages.append(_stage(template, "complete_or_available", [], False, ["PKCS seed and valid-prefix pipeline artifacts exist"]))
    return family_state_record(
        "pkcs_container_parsing",
        "external_pending",
        stages,
        {
            "seed_ready": True,
            "valid_prefix_pipeline_done": True,
            "full_consumption_gap_candidate": full,
            "triage": "caller_must_check_consumption" if caller_must == full and full else "needs_review",
            "app_level_check": "external_assigned_or_pending",
            "next_gate": "wait_pkcs_app_level_consumption_check",
        },
    )


def build_family_pipeline_state(repo_root: Path, registry: dict[str, Any]) -> dict[str, Any]:
    families = [asn1_state(repo_root, registry), pkcs_state(repo_root, registry), x509_state(repo_root, registry)]
    return {
        "schema": "family_pipeline_state_v1",
        "generated_at": now_iso(),
        "families": families,
        "summary": {
            "family_count": len(families),
            "external_pending": [f["family"] for f in families if f["status"] == "external_pending"],
            "missing_capability": [f["family"] for f in families if f["status"] == "missing_capability"],
        },
    }


def build_global_pipeline_state(family_state: dict[str, Any]) -> dict[str, Any]:
    summary = family_state.get("summary", {})
    return {
        "schema": "global_pipeline_state_v1",
        "generated_at": now_iso(),
        "mode": "dry_run",
        "scheduler_driven_runtime_loop": "initialized",
        "glm_called": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
        "summary": summary,
    }
