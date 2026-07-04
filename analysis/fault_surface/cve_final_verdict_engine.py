"""Final security verdict engine over unified runtime truth."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


CONFIRMATION_VERDICT = "CVE_CONFIRMED"
NON_EXPLOITABLE_VERDICT = "NON_EXPLOITABLE_INCONSISTENCY"
INSUFFICIENT_VERDICT = "INSUFFICIENT_EVIDENCE"


class CVEFinalVerdictEngine:
    """Fuse unified truth, reconciled oracle, and semantic divergence."""

    schema = "cve_final_verdict_engine_v1"

    def evaluate(
        self,
        unified_runtime_truth: Mapping[str, Any],
        reconciled_oracle_report: Mapping[str, Any],
        semantic_divergence_points: Mapping[str, Any],
        exploitability_score: Mapping[str, Any],
    ) -> dict[str, Any]:
        usable_rows = [
            row
            for row in unified_runtime_truth.get("rows", [])
            if isinstance(row, Mapping) and row.get("truth_status") == "authoritative"
        ]
        semantic_inconsistency = _has_semantic_inconsistency(
            reconciled_oracle_report,
            semantic_divergence_points,
        )
        runtime_reproducible = unified_runtime_truth.get("status") == "unified" and len(usable_rows) >= 2
        security_api_mismatch = _security_api_mismatch(semantic_divergence_points)
        score = int(exploitability_score.get("exploitability_score", 0) or 0)
        if not runtime_reproducible:
            verdict = INSUFFICIENT_VERDICT
            reason = "missing_reproducible_unified_runtime_trace"
        elif semantic_inconsistency and security_api_mismatch and score > 0:
            verdict = CONFIRMATION_VERDICT
            reason = "unified_runtime_semantic_security_mismatch"
        else:
            verdict = NON_EXPLOITABLE_VERDICT
            reason = "divergence_without_security_impact_or_allowed_contract_behavior"
        severity = _severity_assessment(verdict, score, semantic_inconsistency, security_api_mismatch)
        final_security_verdict = {
            "schema": "final_security_verdict_v1",
            "verdict": verdict,
            "reason": reason,
            "runtime_reproducible_divergence": runtime_reproducible,
            "cross_library_semantic_inconsistency": semantic_inconsistency,
            "security_impacting_api_mismatch": security_api_mismatch,
            "exploitability_score": score,
            "fallback_used": False,
            "partial_trace_inference_used": False,
            "mutation_executed": False,
            "candidate_queue_written": False,
            "claim_level": "final_verdict_requires_human_review_before_disclosure",
        }
        report = {
            "schema": "cve_candidate_report_v2",
            "verdict": verdict,
            "unified_truth_status": unified_runtime_truth.get("status"),
            "oracle_input": reconciled_oracle_report.get("oracle_input"),
            "semantic_divergence_point_count": _point_count(semantic_divergence_points),
            "candidate_queue_written": False,
            "claim_level": "classification_artifact_only",
        }
        return {
            "schema": self.schema,
            "final_security_verdict": final_security_verdict,
            "cve_candidate_report": report,
            "severity_assessment": severity,
            "candidate_queue_written": False,
        }


def evaluate(
    unified_runtime_truth: Mapping[str, Any],
    reconciled_oracle_report: Mapping[str, Any],
    semantic_divergence_points: Mapping[str, Any],
    exploitability_score: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate final security verdict."""

    return CVEFinalVerdictEngine().evaluate(
        unified_runtime_truth,
        reconciled_oracle_report,
        semantic_divergence_points,
        exploitability_score,
    )


def _has_semantic_inconsistency(
    reconciled_oracle_report: Mapping[str, Any],
    semantic_divergence_points: Mapping[str, Any],
) -> bool:
    if reconciled_oracle_report.get("semantic_oracle_divergence") or reconciled_oracle_report.get("state_oracle_divergence"):
        return True
    return _point_count(semantic_divergence_points) > 0


def _security_api_mismatch(semantic_divergence_points: Mapping[str, Any]) -> bool:
    points = _points(semantic_divergence_points)
    if not points:
        return False
    terms = ("signature", "key_usage", "lifecycle", "security", "verify", "decrypt", "encrypt")
    for point in points:
        text = " ".join(str(value) for value in point.values())
        if any(term in text for term in terms):
            return True
    return False


def _severity_assessment(
    verdict: str,
    score: int,
    semantic_inconsistency: bool,
    security_api_mismatch: bool,
) -> dict[str, Any]:
    if verdict == CONFIRMATION_VERDICT and score >= 80:
        severity = "impact_elevated"
    elif verdict == CONFIRMATION_VERDICT:
        severity = "impact_moderate"
    elif verdict == INSUFFICIENT_VERDICT:
        severity = "insufficient_evidence"
    else:
        severity = "non_abusable_or_contract_allowed"
    return {
        "schema": "severity_assessment_v1",
        "severity_classification": severity,
        "exploitability_score": score,
        "semantic_inconsistency": semantic_inconsistency,
        "security_api_mismatch": security_api_mismatch,
        "candidate_queue_written": False,
    }


def _point_count(source: Mapping[str, Any]) -> int:
    return len(_points(source))


def _points(source: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    for key in ("points", "breakpoints", "semantic_divergence_points"):
        value = source.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    return []
