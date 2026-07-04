"""Map runtime consistency evidence back to security candidate dimensions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SECURITY_FLAGS = (
    "key_usage_semantic_consistency_break",
    "lifecycle_security_guarantee_inconsistency",
    "signature_validity_equivalence_break",
)


class SecurityCandidateVerifier:
    """Verify whether candidate dimensions are supported by runtime evidence."""

    schema = "security_candidate_verifier_v1"

    def verify(
        self,
        security_candidate: Mapping[str, Any],
        runtime_truth_matrix: Mapping[str, Any],
        consistency_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        consistency_report = consistency_result.get("consistency_report", {})
        inconsistency_type = consistency_result.get("inconsistency_type", {})
        flags = _collect_flags(security_candidate)
        dimension_results = {
            "key_usage_semantic_consistency_break": _supported(
                "key_usage_result",
                flags,
                consistency_report,
            ),
            "lifecycle_security_guarantee_inconsistency": _supported(
                "lifecycle_state",
                flags,
                consistency_report,
            ),
            "signature_validity_equivalence_break": _supported(
                "signature_validity",
                flags,
                consistency_report,
            ),
        }
        verified = (
            consistency_report.get("consistency") == "inconsistent"
            and any(item["runtime_supported"] for item in dimension_results.values())
        )
        verified_security_candidate = {
            "schema": "verified_security_candidate_v1",
            "status": "VERIFIED_SECURITY_INCONSISTENCY" if verified else "FALSE_POSITIVE",
            "runtime_truth_status": runtime_truth_matrix.get("status"),
            "inconsistency_type": inconsistency_type.get("type"),
            "dimension_results": dimension_results,
            "candidate_queue_written": False,
            "claim_level": "runtime_validation_status_only",
        }
        false_positive_report = {
            "schema": "false_positive_report_v1",
            "is_false_positive": not verified,
            "reason": "runtime_security_outcome_consistent_or_missing_truth" if not verified else "not_applicable",
            "analysis_layer_flags": flags,
            "runtime_supported_flags": [
                name for name, item in dimension_results.items() if item.get("runtime_supported")
            ],
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "verified_security_candidate": verified_security_candidate,
            "false_positive_report": false_positive_report,
            "candidate_queue_written": False,
        }


def verify(
    security_candidate: Mapping[str, Any],
    runtime_truth_matrix: Mapping[str, Any],
    consistency_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Map runtime consistency evidence to candidate dimensions."""

    return SecurityCandidateVerifier().verify(security_candidate, runtime_truth_matrix, consistency_result)


def _collect_flags(security_candidate: Mapping[str, Any]) -> list[str]:
    flags = security_candidate.get("security_violation_flags")
    if not flags and isinstance(security_candidate.get("security_violation_summary"), Mapping):
        flags = security_candidate["security_violation_summary"].get("security_violation_flags")
    if not isinstance(flags, list):
        return []
    return [str(flag) for flag in flags]


def _supported(
    field: str,
    flags: list[str],
    consistency_report: Mapping[str, Any],
) -> dict[str, Any]:
    flag = _flag_for_field(field)
    inconsistent_fields = consistency_report.get("inconsistent_fields") or []
    return {
        "analysis_flag_present": flag in flags,
        "runtime_field": field,
        "runtime_supported": flag in flags and field in inconsistent_fields,
        "field_outcomes": (consistency_report.get("field_outcomes") or {}).get(field, {}),
    }


def _flag_for_field(field: str) -> str:
    return {
        "key_usage_result": "key_usage_semantic_consistency_break",
        "lifecycle_state": "lifecycle_security_guarantee_inconsistency",
        "signature_validity": "signature_validity_equivalence_break",
    }[field]
