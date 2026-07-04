"""Readiness package assembly for externally validated security reports."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


REQUIRED_CONFIRMATION_LIBRARIES = ("mbedtls", "wolfssl", "botan")


class CVECandidatePackager:
    """Package scoring and replay material into a guarded readiness bundle."""

    schema = "cve_candidate_packager_v1"

    def package(
        self,
        seed_context: Mapping[str, Any],
        security_candidate: Mapping[str, Any],
        exploitability: Mapping[str, Any],
        repro_bundle: Mapping[str, Any],
        *,
        threshold: int = 75,
    ) -> dict[str, Any]:
        confirmation_matrix = _confirmation_matrix(seed_context, security_candidate)
        reproducibility_matrix = _reproducibility_matrix(
            seed_context,
            repro_bundle,
            confirmation_matrix,
        )
        score = int(exploitability.get("exploitability_score", 0) or 0)
        readiness_status = (
            "ready_for_external_validation"
            if score >= threshold and _required_libraries_have_evidence(confirmation_matrix)
            else "demoted_candidate"
        )
        report = {
            "schema": "cve_candidate_report_v1",
            "readiness_status": readiness_status,
            "exploitability_threshold": threshold,
            "exploitability_score": score,
            "severity_classification": exploitability.get("severity_classification"),
            "same_seed_required": True,
            "same_semantic_break_type_required": True,
            "cross_library_confirmation_required": list(REQUIRED_CONFIRMATION_LIBRARIES),
            "cross_library_confirmation_status": confirmation_matrix.get("overall_status"),
            "minimal_reproducer_available": bool(repro_bundle.get("minimal_reproducer.c")),
            "candidate_queue_written": False,
            "claim_level": "readiness_packaging_only_no_confirmation",
        }
        severity_score = {
            "schema": "severity_score_v1",
            "exploitability_score": score,
            "severity_classification": exploitability.get("severity_classification"),
            "dimension_scores": exploitability.get("dimension_scores", {}),
            "claim_level": "scoring_only",
        }
        return {
            "schema": self.schema,
            "readiness_status": readiness_status,
            "exploitability": exploitability,
            "minimal_reproducer": repro_bundle,
            "cve_candidate_report": report,
            "severity_score": severity_score,
            "cross_library_confirmation_matrix": confirmation_matrix,
            "reproducibility_matrix": reproducibility_matrix,
            "report_payloads": {
                "cve_candidate_report.yaml": report,
                "exploitability_score.yaml": exploitability,
                "severity_score.yaml": severity_score,
                "minimal_reproducer.c": repro_bundle.get("minimal_reproducer.c", ""),
                "repro_steps.yaml": repro_bundle.get("repro_steps.yaml", {}),
                "dependency_manifest.yaml": repro_bundle.get("dependency_manifest.yaml", {}),
                "cross_library_confirmation_matrix.yaml": confirmation_matrix,
                "reproducibility_matrix.yaml": reproducibility_matrix,
            },
            "candidate_queue_written": False,
            "claim_level": "external_validation_readiness_only",
        }


def package(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
    exploitability: Mapping[str, Any],
    repro_bundle: Mapping[str, Any],
    *,
    threshold: int = 75,
) -> dict[str, Any]:
    """Package readiness material without modifying queue state."""

    return CVECandidatePackager().package(
        seed_context,
        security_candidate,
        exploitability,
        repro_bundle,
        threshold=threshold,
    )


def _confirmation_matrix(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> dict[str, Any]:
    seed_id = str(seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed")
    break_type = _semantic_break_type(security_candidate)
    available = _available_library_names(seed_context, security_candidate)
    rows = []
    for library in REQUIRED_CONFIRMATION_LIBRARIES:
        has_library = library in available
        has_divergence = _has_divergence_evidence(security_candidate)
        rows.append(
            {
                "library": library,
                "same_seed": seed_id != "unknown_seed",
                "same_semantic_break_type": bool(break_type),
                "consistent_failure_pattern_or_divergence_evidence": has_library and has_divergence,
                "confirmation_status": "evidence_ready" if has_library and has_divergence else "missing_target_evidence",
            }
        )
    return {
        "schema": "cross_library_confirmation_matrix_v1",
        "seed_id": seed_id,
        "semantic_break_type": break_type,
        "required_libraries": list(REQUIRED_CONFIRMATION_LIBRARIES),
        "rows": rows,
        "overall_status": "complete" if all(row["confirmation_status"] == "evidence_ready" for row in rows) else "incomplete",
        "candidate_queue_written": False,
    }


def _reproducibility_matrix(
    seed_context: Mapping[str, Any],
    repro_bundle: Mapping[str, Any],
    confirmation_matrix: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "reproducibility_matrix_v1",
        "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
        "same_seed_replay": True,
        "deterministic_seed_replay": bool(repro_bundle.get("deterministic_seed_replay", True)),
        "fuzz_required": False,
        "runtime_pressure_required": False,
        "glm_required": False,
        "rag_reindex_required": False,
        "cross_library_confirmation_status": confirmation_matrix.get("overall_status"),
        "rows": confirmation_matrix.get("rows", []),
        "candidate_queue_written": False,
    }


def _available_library_names(
    seed_context: Mapping[str, Any],
    security_candidate: Mapping[str, Any],
) -> set[str]:
    raw = (
        seed_context.get("target_libraries")
        or seed_context.get("targets")
        or security_candidate.get("target_libraries")
        or []
    )
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raw = []
    return {str(item).split("-", 1)[0].lower() for item in raw}


def _semantic_break_type(security_candidate: Mapping[str, Any]) -> str:
    flags = security_candidate.get("security_violation_flags") or []
    if isinstance(flags, list) and flags:
        return str(flags[0])
    summary = security_candidate.get("security_violation_summary")
    if isinstance(summary, Mapping):
        summary_flags = summary.get("security_violation_flags")
        if isinstance(summary_flags, list) and summary_flags:
            return str(summary_flags[0])
    return "security_relevant_inconsistency"


def _has_divergence_evidence(security_candidate: Mapping[str, Any]) -> bool:
    if security_candidate.get("security_violation_flags"):
        return True
    report = security_candidate.get("security_divergence_report")
    if isinstance(report, Mapping) and int(report.get("security_divergence_score", 0) or 0) > 0:
        return True
    return bool(security_candidate.get("crypto_semantic_breakpoints", {}).get("breakpoints", []))


def _required_libraries_have_evidence(confirmation_matrix: Mapping[str, Any]) -> bool:
    rows = confirmation_matrix.get("rows", [])
    return bool(rows) and all(
        isinstance(row, Mapping) and row.get("confirmation_status") == "evidence_ready"
        for row in rows
    )
