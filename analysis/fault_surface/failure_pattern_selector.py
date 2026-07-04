"""Select failure-oriented patterns from oracle divergence signals."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PATTERN_KIND_BY_DIVERGENCE = {
    "node_divergence": "lifecycle_boundary",
    "transition_divergence": "unstable_transition",
    "error_path_divergence": "error_recovery_path",
    "execution_path_mismatch": "unstable_transition",
    "state_divergence": "lifecycle_boundary",
    "silent_failure": "error_recovery_path",
    "cross_library_divergence": "cross_object_contamination_point",
}


def select_failure_patterns(oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Extract reusable failure patterns from cross-library oracle output."""

    report = _divergence_report(oracle_output)
    observations = _observations(report)
    selected = []
    for index, observation in enumerate(observations):
        kind = str(observation.get("kind", "unknown"))
        pattern_kind = PATTERN_KIND_BY_DIVERGENCE.get(kind, "unstable_transition")
        selected.append(
            {
                "pattern_id": f"failure_pattern_{index:03d}",
                "pattern_kind": pattern_kind,
                "source_divergence_kind": kind,
                "selector_reason": _reason(pattern_kind),
                "source_observation": observation,
                "template_layer_reusable": True,
                "candidate_queue_written": False,
            }
        )
    if not selected and _score(report, "divergence_score") > 0:
        selected.append(
            {
                "pattern_id": "failure_pattern_score_only_000",
                "pattern_kind": "unstable_transition",
                "source_divergence_kind": "score_only_divergence",
                "selector_reason": "divergence_score_without_structured_observation",
                "source_observation": {
                    "divergence_score": _score(report, "divergence_score"),
                    "mismatch_score": _score(report, "mismatch_score"),
                    "instability_score": _score(report, "instability_score"),
                },
                "template_layer_reusable": True,
                "candidate_queue_written": False,
            }
        )
    return {
        "schema": "selected_failure_patterns_v1",
        "selected_failure_patterns": selected,
        "selected_failure_pattern_count": len(selected),
        "selection_status": "ok" if selected else "no_failure_patterns_selected",
        "candidate_queue_written": False,
    }


def _divergence_report(oracle_output: Mapping[str, Any]) -> Mapping[str, Any]:
    report = oracle_output.get("cross_library_divergence_report") or oracle_output.get("divergence_report")
    return report if isinstance(report, Mapping) else oracle_output


def _observations(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    observations = report.get("observations")
    if isinstance(observations, list):
        return [dict(item) for item in observations if isinstance(item, Mapping)]
    return []


def _score(report: Mapping[str, Any], key: str) -> int:
    try:
        return int(report.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _reason(pattern_kind: str) -> str:
    reasons = {
        "unstable_transition": "divergence_points_to_transition_sensitive_execution",
        "error_recovery_path": "divergence_points_to_error_path_recovery_or_continuation",
        "lifecycle_boundary": "divergence_points_to_state_boundary_or_lifecycle_gap",
        "cross_object_contamination_point": "divergence_points_to_object_state_mapping_gap",
    }
    return reasons.get(pattern_kind, "divergence_points_to_failure_surface")
