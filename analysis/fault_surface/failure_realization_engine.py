"""Failure realization from stressed execution attempts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class FailureRealizationEngine:
    """Evaluate pressure-applied execution attempts for observable deltas."""

    schema = "failure_realization_engine_v1"

    def evaluate(self, stressed_execution: Mapping[str, Any]) -> dict[str, Any]:
        stressed = stressed_execution.get("stressed_execution", {}).get("results", [])
        rows = []
        for index, result in enumerate(stressed if isinstance(stressed, list) else []):
            if not isinstance(result, Mapping):
                continue
            rows.append(_attempt_observation(index, result))
        report = {
            "schema": "failure_realization_report_v1",
            "attempt_count": len(rows),
            "runtime_pressure_executed": bool(stressed_execution.get("runtime_pressure_executed")),
            "crash_emergence_count": sum(1 for row in rows if row["crash_emergence"]),
            "sanitizer_emergence_count": sum(1 for row in rows if row["sanitizer_emergence"]),
            "state_corruption_emergence_count": sum(1 for row in rows if row["state_corruption_emergence"]),
            "semantic_violation_emergence_count": sum(1 for row in rows if row["semantic_violation_emergence"]),
            "attempts": rows,
            "candidate_queue_written": False,
            "status": "ok" if rows else "no_stressed_execution_results",
        }
        return {
            "schema": self.schema,
            "failure_realization_report": report,
            "candidate_queue_written": False,
            "claim_level": "runtime_pressure_observation_only",
        }


def evaluate(stressed_execution: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate stressed execution attempts."""

    return FailureRealizationEngine().evaluate(stressed_execution)


def _attempt_observation(index: int, result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "attempt_index": index,
        "pressure_attempt_id": result.get("pressure_attempt_id"),
        "pressure_type": result.get("pressure_type"),
        "crash_emergence": bool(result.get("crash_emergence")),
        "sanitizer_emergence": bool(result.get("sanitizer_emergence")),
        "state_corruption_emergence": bool(result.get("state_corruption_emergence")),
        "semantic_violation_emergence": bool(result.get("semantic_violation_emergence")),
        "classification": "semantic_observation",
        "candidate_queue_written": False,
    }
