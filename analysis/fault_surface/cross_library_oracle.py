"""Supplementary cross-library oracle for fault-surface divergence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def analyze_cross_library_divergence(
    alignment: Mapping[str, Any],
    comparison: Mapping[str, Any],
    mutation_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Aggregate alignment and graph comparison into supplementary scores."""

    observations = _observations(comparison)
    divergence_score = _bounded_score(
        comparison.get("node_divergence_count", 0) * 20
        + comparison.get("transition_divergence_count", 0) * 25
        + comparison.get("error_path_divergence_count", 0) * 30
    )
    mismatch_score = _mismatch_score(alignment, comparison)
    instability_score = _bounded_score(
        divergence_score // 2
        + int(mutation_plan.get("failure_inducing_mutation_count", 0) or 0) * 2
    )
    report = {
        "schema": "cross_library_divergence_report_v1",
        "seed_id": alignment.get("seed_id"),
        "family": alignment.get("family"),
        "oracle_kind": "cross_library_divergence_oracle",
        "detectors": [
            "cross_library_divergence_oracle",
            "execution_path_mismatch_detector",
            "state_mapping_inconsistency_detector",
        ],
        "divergence_score": divergence_score,
        "mismatch_score": mismatch_score,
        "instability_score": instability_score,
        "observation_count": len(observations),
        "observations": observations,
        "candidate_queue_written": False,
        "claim_level": "supplementary_observation_only",
    }
    return {
        "schema": "cross_library_oracle_v1",
        "cross_library_divergence_report": report,
        "divergence_score": divergence_score,
        "mismatch_score": mismatch_score,
        "instability_score": instability_score,
        "oracle_status": "ok" if alignment.get("aligned_libraries") else "no_aligned_graphs",
        "candidate_queue_written": False,
        "claim_level": "supplementary_observation_only",
    }


def _observations(comparison: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("node_divergence", "transition_divergence", "error_path_divergence"):
        value = comparison.get(key)
        if isinstance(value, list):
            rows.extend(dict(item) for item in value if isinstance(item, Mapping))
    return rows


def _mismatch_score(alignment: Mapping[str, Any], comparison: Mapping[str, Any]) -> int:
    alignment_report = alignment.get("graph_alignment_report") or {}
    missing = alignment_report.get("missing_canonical_states_by_library") or {}
    missing_count = sum(len(states) for states in missing.values() if isinstance(states, list))
    comparison_count = int(comparison.get("total_divergence_count", 0) or 0)
    return _bounded_score(missing_count * 5 + comparison_count * 20)


def _bounded_score(value: int) -> int:
    return max(0, min(100, int(value)))
