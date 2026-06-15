"""Task queue record helpers for dry-run scheduler runtime loops."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def task_record(
    task_name: str,
    family: str,
    priority: str,
    status: str,
    reason: str,
    required_inputs: list[str],
    blocked_by: list[str],
    allowed_to_run_now: bool,
    owner: str,
) -> dict[str, Any]:
    return {
        "task_name": task_name,
        "family": family,
        "priority": priority,
        "status": status,
        "reason": reason,
        "required_inputs": required_inputs,
        "blocked_by": blocked_by,
        "allowed_to_run_now": allowed_to_run_now,
        "owner": owner,
    }


def build_task_queue(family_status: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    statuses = family_status.get("families", {})
    asn1 = statuses.get("asn1_nested_boundary", {})
    pkcs = statuses.get("pkcs_container_parsing", {})
    project = statuses.get("project_structure", {})
    priorities = policy.get("default_priorities", {}) or {}

    tasks = [
        task_record(
            "external_validation_import_gate_v1",
            "asn1_nested_boundary",
            priorities.get("external_validation_import_gate_v1", "high"),
            "external_pending" if asn1.get("candidates") == "external_validation_pending" else "blocked",
            "ASN.1 full-consumption candidates are assigned to teammate validation.",
            [
                "artifacts/sprints/runtime_feedback_integration_v1/candidate_queue/external_validation_pending_candidates.yaml",
                "artifacts/sprints/family_loop_closure_report_v1/candidate_status/candidate_status.yaml",
            ],
            ["teammate_external_validation"],
            False,
            "teammate",
        ),
        task_record(
            "x509_family_template_seed_discovery_v1",
            "x509_asn1_inner_boundary",
            priorities.get("x509_family_template_seed_discovery_v1", "high"),
            "ready",
            "X.509 is adjacent to ASN.1 and can reuse current oracle instrumentation without waiting on PKCS app-level validation.",
            [
                "docs/PROJECT_STRUCTURE.md",
                "artifacts/sprints/project_structure_refactor_phase7_docs_and_imports_v1/validation/docs_imports_quality_checks.yaml",
            ],
            [],
            True,
            "local",
        ),
        task_record(
            "more_asn1_valid_prefix_cases_v1",
            "asn1_nested_boundary",
            priorities.get("more_asn1_valid_prefix_cases_v1", "medium"),
            "ready" if asn1.get("loop_closed") is True else "blocked",
            "ASN.1 loop is closed enough for additional valid-prefix cases while external validation remains pending.",
            [
                "artifacts/sprints/family_loop_closure_report_v1/family_status/family_status.yaml",
                "artifacts/sprints/runtime_feedback_integration_v1/candidate_queue/external_validation_pending_candidates.yaml",
            ],
            [],
            bool(asn1.get("loop_closed") is True),
            "local",
        ),
        task_record(
            "wait_pkcs_app_level_consumption_check",
            "pkcs_container_parsing",
            priorities.get("wait_pkcs_app_level_consumption_check", "high"),
            "external_pending",
            "PKCS local triage classified candidates as caller_must_check_consumption; app-level caller behavior is teammate-owned.",
            [
                "artifacts/sprints/pkcs_candidate_external_validation_v1/triage/pkcs_candidate_triage.yaml",
                "artifacts/sprints/pkcs_candidate_external_validation_v1/triage/teammate_validation_notes.md",
            ],
            ["pkcs_app_level_consumption_check_v1"],
            False,
            "teammate",
        ),
    ]
    return {
        "schema": "scheduler_task_queue_v1",
        "generated_at": now_iso(),
        "scheduler_mode": "dry_run",
        "tasks": tasks,
        "summary": {
            "total_tasks": len(tasks),
            "ready": len([t for t in tasks if t["status"] == "ready"]),
            "blocked": len([t for t in tasks if t["status"] == "blocked"]),
            "external_pending": len([t for t in tasks if t["status"] == "external_pending"]),
            "project_structure_refactor_done": bool(project.get("refactor_done")),
            "pkcs_app_level_check": pkcs.get("app_level_check", ""),
        },
    }


def split_tasks(queue: dict[str, Any], status: str) -> dict[str, Any]:
    tasks = [t for t in queue.get("tasks", []) if t.get("status") == status]
    return {
        "schema": f"scheduler_{status}_tasks_v1",
        "generated_at": now_iso(),
        "status": status,
        "tasks": tasks,
        "summary": {"total_tasks": len(tasks)},
    }
