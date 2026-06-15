"""Scheduler proposal helpers."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def build_scheduler_proposal() -> dict[str, Any]:
    return {
        "schema": "scheduler_feedback_proposal_v1",
        "generated_at": now_iso(),
        "proposals": [
            {
                "priority": "high",
                "task": "valid_seed_discovery_pkcs_v1",
                "reason": "pkcs_container_parsing has pending seed requirement",
            },
            {
                "priority": "high",
                "task": "more_asn1_valid_prefix_cases_v1",
                "reason": "accepted path observed and full-consumption candidates appeared",
            },
            {
                "priority": "medium",
                "task": "x509_family_template_seed_discovery_v1",
                "reason": "x509 is adjacent to ASN.1 and can reuse oracle instrumentation",
            },
            {
                "priority": "medium",
                "task": "external_validation_import_gate_v1",
                "reason": "full_consumption candidates are pending teammate validation",
            },
        ],
        "do_not_schedule_yet": [
            "cross_library_differential_run_v1",
            "pattern_bank_import_v1",
            "confirmed_vulnerability_report_v1",
        ],
    }


def proposal_tasks(scheduler: dict[str, Any], priority: str) -> list[str]:
    return [
        str(item.get("task"))
        for item in scheduler.get("proposals", []) or []
        if isinstance(item, dict) and item.get("priority") == priority and item.get("task")
    ]
