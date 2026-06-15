"""Candidate queue helpers for external validation handoff."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def candidate_items(labels_doc: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in labels_doc.get("labels", []) or []:
        if item.get("candidate_label") != "full_consumption_gap_candidate":
            continue
        out.append(
            {
                "case_id": item.get("case_id", ""),
                "family": "asn1_nested_boundary",
                "target_library": "openssl",
                "candidate_type": "full_consumption_gap_candidate",
                "observed_condition": "accepted_true_and_full_consumption_false",
                "local_triage_performed": False,
                "external_validation_status": "pending",
                "assigned_to": "teammate",
                "claim_policy": {
                    "confirmed_vulnerability": False,
                    "cve": False,
                    "exploitable": False,
                },
            }
        )
    return out


def build_queue(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "external_validation_pending_candidates_v1",
        "generated_at": now_iso(),
        "source_task": "valid_prefix_pipeline_to_analyze_v1",
        "candidates": candidates,
        "summary": {
            "total_candidates": len(candidates),
            "pending_external_validation": len(candidates),
        },
    }


def build_handoff(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "teammate_validation_handoff_v1",
        "generated_at": now_iso(),
        "local_triage_performed": False,
        "candidate_count": len(candidates),
        "candidate_type": "full_consumption_gap_candidate",
        "requested_external_validation": [
            "verify whether candidates are expected OpenSSL prefix-parse behavior",
            "verify whether any candidate can rise to app-level validation gap candidate",
            "check whether a real upper-layer caller fails to check full consumption",
            "decide whether a minimal reproducer is needed",
        ],
        "do_not_answer_in_this_task": [
            "tail content",
            "consumed_len/input_len details",
            "API semantic final classification",
            "confirmed vulnerability / CVE / exploitable status",
        ],
        "candidates": [c.get("case_id") for c in candidates],
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


ALLOWED_CANDIDATE_LABELS = {
    "normal_reject",
    "normal_accept",
    "crash_candidate",
    "sanitizer_candidate",
    "full_consumption_gap_candidate",
    "semantic_divergence_candidate",
    "container_boundary_candidate",
    "lifecycle_divergence_candidate",
    "unknown_new_candidate",
    "needs_triage",
    "oracle_incomplete",
    "external_validation_pending",
}


def build_family_candidate_queue(
    labels: list[dict[str, Any]],
    *,
    family: str,
    source_task: str,
) -> dict[str, Any]:
    candidates = []
    for item in labels:
        label = str(item.get("candidate_label") or "needs_triage")
        if label not in ALLOWED_CANDIDATE_LABELS:
            label = "needs_triage"
        candidates.append(
            {
                "case_id": item.get("case_id", ""),
                "family": family,
                "target_library": item.get("target_library", "openssl"),
                "candidate_label": label,
                "mutation_strategy": item.get("mutation_strategy", ""),
                "reason": item.get("reason", ""),
                "triage_required": bool(item.get("triage_required")),
                "external_validation_status": "pending"
                if label
                in {
                    "crash_candidate",
                    "sanitizer_candidate",
                    "full_consumption_gap_candidate",
                    "semantic_divergence_candidate",
                    "container_boundary_candidate",
                    "lifecycle_divergence_candidate",
                    "unknown_new_candidate",
                    "needs_triage",
                }
                else "not_required",
                "claim_policy": {
                    "confirmed_vulnerability": False,
                    "cve": False,
                    "exploitable": False,
                },
            }
        )
    summary: dict[str, Any] = {"total_candidates": len(candidates)}
    for label in sorted(ALLOWED_CANDIDATE_LABELS):
        summary[label] = len([item for item in candidates if item.get("candidate_label") == label])
    return {
        "schema": "family_candidate_queue_v1",
        "generated_at": now_iso(),
        "source_task": source_task,
        "family": family,
        "allowed_candidate_labels": sorted(ALLOWED_CANDIDATE_LABELS),
        "forbidden_labels": ["confirmed vulnerability", "CVE", "exploitable"],
        "candidates": candidates,
        "summary": summary,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }
