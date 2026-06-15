"""Scan existing sprint artifacts into scheduler family status records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import load_yaml, now_iso


INPUT_ARTIFACTS = [
    "artifacts/sprints/family_loop_closure_report_v1/",
    "artifacts/sprints/runtime_feedback_integration_v1/",
    "artifacts/sprints/valid_seed_discovery_pkcs_v1/",
    "artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/",
    "artifacts/sprints/pkcs_candidate_external_validation_v1/",
    "artifacts/sprints/project_structure_refactor_phase7_docs_and_imports_v1/",
]


def artifact_presence(repo_root: Path) -> dict[str, Any]:
    scanned = []
    missing = []
    for item in INPUT_ARTIFACTS:
        path = repo_root / item
        row = {"path": item, "exists": path.exists()}
        scanned.append(row)
        if not path.exists():
            missing.append(item)
    optional = ["artifacts/sprints/pkcs_app_level_consumption_check_v1/"]
    missing_optional = [p for p in optional if not (repo_root / p).exists()]
    return {"scanned_artifacts": scanned, "missing_required": missing, "missing_optional": missing_optional}


def scan_asn1(repo_root: Path) -> dict[str, Any]:
    family_doc = load_yaml(repo_root / "artifacts/sprints/family_loop_closure_report_v1/family_status/family_status.yaml")
    candidate_doc = load_yaml(
        repo_root
        / "artifacts/sprints/runtime_feedback_integration_v1/candidate_queue/external_validation_pending_candidates.yaml"
    )
    family_row = {}
    for row in family_doc.get("families", []) or []:
        if row.get("family") == "asn1_nested_boundary":
            family_row = row
            break
    pending = int((candidate_doc.get("summary") or {}).get("pending_external_validation", 0) or 0)
    loop_closed = str(family_row.get("closure_status", "")).startswith("framework_loop_closed")
    return {
        "family": "asn1_nested_boundary",
        "loop_closed": loop_closed,
        "candidates": "external_validation_pending" if pending > 0 else "none",
        "external_validation_pending": pending,
        "next": "wait_external_validation" if pending > 0 else "more_asn1_valid_prefix_cases_v1",
        "source_artifacts": [
            "artifacts/sprints/family_loop_closure_report_v1/family_status/family_status.yaml",
            "artifacts/sprints/runtime_feedback_integration_v1/candidate_queue/external_validation_pending_candidates.yaml",
        ],
    }


def scan_pkcs(repo_root: Path) -> dict[str, Any]:
    seed_qc = load_yaml(
        repo_root / "artifacts/sprints/valid_seed_discovery_pkcs_v1/validation/valid_seed_discovery_quality_checks.yaml"
    )
    pipeline_qc = load_yaml(
        repo_root
        / "artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/validation/pkcs_valid_prefix_pipeline_quality_checks.yaml"
    )
    analysis_doc = load_yaml(
        repo_root / "artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/analyze/oracle_aware_analysis.yaml"
    )
    triage_doc = load_yaml(
        repo_root / "artifacts/sprints/pkcs_candidate_external_validation_v1/triage/pkcs_candidate_triage.yaml"
    )
    triage_summary = triage_doc.get("summary", {}) or {}
    full_candidates = int((analysis_doc.get("summary") or {}).get("full_consumption_gap_candidate", 0) or 0)
    caller_must = int(triage_summary.get("caller_must_check_consumption", 0) or 0)
    return {
        "family": "pkcs_container_parsing",
        "valid_seed_ready": bool(seed_qc.get("verified_seed_count", 0) and seed_qc.get("quality_status") == "pass"),
        "valid_prefix_pipeline_done": bool(pipeline_qc.get("quality_status") == "pass"),
        "full_consumption_gap_candidate": full_candidates,
        "triage": "caller_must_check_consumption" if caller_must == full_candidates and full_candidates else "needs_review",
        "app_level_check": "external_assigned_or_pending",
        "next": "wait_pkcs_app_level_check",
        "source_artifacts": [
            "artifacts/sprints/valid_seed_discovery_pkcs_v1/validation/valid_seed_discovery_quality_checks.yaml",
            "artifacts/sprints/pkcs_valid_prefix_pipeline_to_analyze_v1/analyze/oracle_aware_analysis.yaml",
            "artifacts/sprints/pkcs_candidate_external_validation_v1/triage/pkcs_candidate_triage.yaml",
        ],
    }


def scan_project_structure(repo_root: Path) -> dict[str, Any]:
    docs_qc = load_yaml(
        repo_root
        / "artifacts/sprints/project_structure_refactor_phase7_docs_and_imports_v1/validation/docs_imports_quality_checks.yaml"
    )
    return {
        "family": "project_structure",
        "refactor_done": docs_qc.get("quality_status") == "pass",
        "tools_policy_documented": bool(docs_qc.get("tools_policy_documented")),
        "module_boundaries_documented": bool(docs_qc.get("module_boundaries_documented")),
        "next": "keep_tools_as_thin_wrappers",
        "source_artifacts": [
            "artifacts/sprints/project_structure_refactor_phase7_docs_and_imports_v1/validation/docs_imports_quality_checks.yaml"
        ],
    }


def build_family_status(repo_root: Path) -> dict[str, Any]:
    presence = artifact_presence(repo_root)
    families = {
        "asn1_nested_boundary": scan_asn1(repo_root),
        "pkcs_container_parsing": scan_pkcs(repo_root),
        "project_structure": scan_project_structure(repo_root),
    }
    return {
        "schema": "scheduler_family_status_v1",
        "generated_at": now_iso(),
        "families": families,
        "artifact_presence": presence,
        "summary": {
            "families_seen": len(families),
            "missing_required_artifacts": len(presence["missing_required"]),
            "external_pending_families": [
                name
                for name, status in families.items()
                if status.get("candidates") == "external_validation_pending"
                or status.get("app_level_check") == "external_assigned_or_pending"
            ],
        },
    }


def build_global_status(family_status: dict[str, Any]) -> dict[str, Any]:
    presence = family_status.get("artifact_presence", {})
    return {
        "schema": "scheduler_global_runtime_status_v1",
        "generated_at": now_iso(),
        "scheduler_driven_runtime_loop": "now_initialized",
        "mode": "dry_run",
        "experiments_executed": False,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
        "artifact_scan": presence,
        "next_decision_basis": [
            "family status from existing sprint artifacts",
            "candidate queues and external pending records",
            "seed manifest and PKCS triage outputs",
        ],
    }
