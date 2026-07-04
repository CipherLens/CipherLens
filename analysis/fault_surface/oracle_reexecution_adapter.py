"""Oracle re-execution delta adapter for pressure-amplified attempts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def compare(
    pre_pressure_oracle: Mapping[str, Any],
    failure_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare pre-pressure oracle output with post-pressure realization."""

    pre_report = pre_pressure_oracle.get("cross_library_divergence_report") or pre_pressure_oracle
    realization = failure_result.get("failure_realization_report") or failure_result
    pre_divergence = _score(pre_report, "divergence_score")
    pre_instability = _score(pre_report, "instability_score")
    post_pressure_signal = (
        int(realization.get("crash_emergence_count", 0) or 0) * 30
        + int(realization.get("sanitizer_emergence_count", 0) or 0) * 25
        + int(realization.get("state_corruption_emergence_count", 0) or 0) * 20
        + int(realization.get("semantic_violation_emergence_count", 0) or 0) * 15
    )
    post_divergence = min(100, pre_divergence + post_pressure_signal)
    post_instability = min(100, pre_instability + post_pressure_signal)
    report = {
        "schema": "oracle_delta_report_v1",
        "pre_pressure": {
            "divergence_score": pre_divergence,
            "instability_score": pre_instability,
            "candidate_queue_written": bool(pre_pressure_oracle.get("candidate_queue_written")),
        },
        "post_pressure": {
            "divergence_score": post_divergence,
            "instability_score": post_instability,
            "crash_emergence_count": realization.get("crash_emergence_count", 0),
            "sanitizer_emergence_count": realization.get("sanitizer_emergence_count", 0),
            "state_corruption_emergence_count": realization.get("state_corruption_emergence_count", 0),
            "semantic_violation_emergence_count": realization.get("semantic_violation_emergence_count", 0),
            "candidate_queue_written": False,
        },
        "delta": {
            "divergence_score_delta": post_divergence - pre_divergence,
            "instability_score_delta": post_instability - pre_instability,
            "crash_emergence": int(realization.get("crash_emergence_count", 0) or 0) > 0,
            "sanitizer_emergence": int(realization.get("sanitizer_emergence_count", 0) or 0) > 0,
            "state_corruption_emergence": int(realization.get("state_corruption_emergence_count", 0) or 0) > 0,
            "semantic_violation_emergence": int(realization.get("semantic_violation_emergence_count", 0) or 0) > 0,
        },
        "candidate_queue_written": False,
        "claim_level": "oracle_delta_observation_only",
    }
    return report


def _score(report: Mapping[str, Any], key: str) -> int:
    try:
        return int(report.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0
