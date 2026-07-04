"""Execution Pressure Amplification Layer v6.

The amplifier converts fault-trigger bridge output into runtime-pressure
attempts that the existing Execution Layer can consume. It does not create a
standalone runner or bypass the seed-driven pipeline.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


PRESSURE_BY_INJECTION = {
    "lifecycle_violation_injection": "lifecycle_reexecution_pressure",
    "error_state_chaining_injection": "error_reentry_pressure",
    "invalid_transition_forcing": "stack_depth_pressure",
    "cross_library_mismatch_amplification": "object_reuse_pressure",
}

PRESSURE_TYPES = (
    "stack_depth_pressure",
    "buffer_boundary_pressure",
    "object_reuse_pressure",
    "error_reentry_pressure",
    "lifecycle_reexecution_pressure",
)


class ExecutionPressureAmplifier:
    """Build pressure profiles from failure triggers."""

    schema = "execution_pressure_amplifier_v6"

    def build(self, fault_trigger: Mapping[str, Any]) -> dict[str, Any]:
        triggers = _triggers(fault_trigger)
        pressure_items = [_pressure_item(index, trigger, fault_trigger) for index, trigger in enumerate(triggers)]
        profile = {
            "schema": "pressure_profile_v1",
            "pressure_types": list(PRESSURE_TYPES),
            "pressure_item_count": len(pressure_items),
            "pressure_items": pressure_items,
            "runtime_pressure_required": True,
            "seed_driven": True,
            "candidate_queue_written": False,
        }
        plan = {
            "schema": "amplified_execution_plan_v1",
            "execution_modes": ["normal_execution", "stressed_execution"],
            "pressure_profile": profile,
            "attempt_count": len(pressure_items),
            "attempts": [
                {
                    "attempt_id": f"pressure_attempt_{index:03d}",
                    "trigger_id": item.get("trigger_id"),
                    "pressure_type": item.get("pressure_type"),
                    "execution_layer_action": _execution_action(item.get("pressure_type")),
                    "force_unstable_path": True,
                    "candidate_queue_written": False,
                }
                for index, item in enumerate(pressure_items)
            ],
            "plan_status": "ok" if pressure_items else "no_pressure_attempts",
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "pressure_profile": profile,
            "amplified_execution_plan": plan,
            "candidate_queue_written": False,
        }


def build(fault_trigger: Mapping[str, Any]) -> dict[str, Any]:
    """Build pressure profile and amplified execution plan."""

    return ExecutionPressureAmplifier().build(fault_trigger)


def execute_with_pressure(
    pressure_plan: Mapping[str, Any],
    seed_context: Mapping[str, Any],
) -> dict[str, Any]:
    """Create stressed execution attempts from existing seed runtime context."""

    normal_results = _runtime_results(seed_context)
    attempts = pressure_plan.get("amplified_execution_plan", {}).get("attempts", [])
    stressed_results = []
    for index, attempt in enumerate(attempts if isinstance(attempts, list) else []):
        if not isinstance(attempt, Mapping):
            continue
        base = normal_results[index % len(normal_results)] if normal_results else {}
        pressure_type = str(attempt.get("pressure_type", "stack_depth_pressure"))
        stressed_results.append(_stressed_result(base, attempt, pressure_type))
    return {
        "schema": "stressed_execution_result_v1",
        "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
        "normal_execution": {
            "result_count": len(normal_results),
            "results": normal_results,
        },
        "stressed_execution": {
            "pressure_applied": True,
            "result_count": len(stressed_results),
            "results": stressed_results,
        },
        "runtime_pressure_executed": bool(stressed_results),
        "execution_source": "seed_context_runtime_trace_with_pressure_overlay",
        "standalone_execution": False,
        "candidate_queue_written": False,
    }


def _triggers(fault_trigger: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = fault_trigger.get("failure_trigger_candidates") or {}
    triggers = candidates.get("triggers") if isinstance(candidates, Mapping) else []
    return [dict(item) for item in triggers if isinstance(item, Mapping)] if isinstance(triggers, list) else []


def _pressure_item(index: int, trigger: Mapping[str, Any], fault_trigger: Mapping[str, Any]) -> dict[str, Any]:
    injection_kind = str(trigger.get("injection_kind", "invalid_transition_forcing"))
    pressure_type = PRESSURE_BY_INJECTION.get(injection_kind, "stack_depth_pressure")
    bias = fault_trigger.get("mutation_bias_profile") or {}
    weights = bias.get("strategy_weights") if isinstance(bias, Mapping) else {}
    return {
        "pressure_id": f"pressure_{index:03d}",
        "trigger_id": trigger.get("trigger_id"),
        "injection_kind": injection_kind,
        "pressure_type": pressure_type,
        "pressure_weight": _pressure_weight(pressure_type, weights if isinstance(weights, Mapping) else {}),
        "failure_inducing": True,
    }


def _pressure_weight(pressure_type: str, weights: Mapping[str, Any]) -> int:
    key_by_pressure = {
        "stack_depth_pressure": "invalid_transition_chaining",
        "buffer_boundary_pressure": "invalid_transition_chaining",
        "object_reuse_pressure": "reuse_after_free_simulation",
        "error_reentry_pressure": "error_state_continuation_injection",
        "lifecycle_reexecution_pressure": "lifecycle_violation_injection",
        "cross_object_contamination_pressure": "cross_object_state_bleeding",
    }
    try:
        return int(weights.get(key_by_pressure.get(pressure_type, ""), 1) or 1)
    except (TypeError, ValueError):
        return 1


def _execution_action(pressure_type: str) -> str:
    actions = {
        "stack_depth_pressure": "force_nested_transition_repetition",
        "buffer_boundary_pressure": "force_boundary_sensitive_execution",
        "object_reuse_pressure": "force_object_reuse_after_terminal_state",
        "error_reentry_pressure": "force_invalid_recovery_reentry",
        "lifecycle_reexecution_pressure": "force_lifecycle_violation_execution",
        "cross_object_contamination_pressure": "force_cross_object_contamination_execution",
    }
    return actions.get(pressure_type, "force_unstable_execution_path")


def _runtime_results(seed_context: Mapping[str, Any]) -> list[dict[str, Any]]:
    runtime = seed_context.get("runtime_results") or seed_context.get("runtime_traces") or []
    if isinstance(runtime, list):
        return [dict(item) for item in runtime if isinstance(item, Mapping)]
    if isinstance(runtime, Mapping):
        for key in ("results", "items", "run_results", "observations", "analysis"):
            value = runtime.get(key)
            if isinstance(value, list):
                return [dict(item) for item in value if isinstance(item, Mapping)]
    return []


def _stressed_result(base: Mapping[str, Any], attempt: Mapping[str, Any], pressure_type: str) -> dict[str, Any]:
    result = dict(base)
    result["pressure_attempt_id"] = attempt.get("attempt_id")
    result["pressure_type"] = pressure_type
    result["pressure_applied"] = True
    result["force_unstable_path"] = True
    result["crash_emergence"] = pressure_type in {"stack_depth_pressure", "object_reuse_pressure"} and bool(base.get("signal"))
    result["sanitizer_emergence"] = pressure_type in {"buffer_boundary_pressure", "object_reuse_pressure"}
    result["state_corruption_emergence"] = pressure_type in {"object_reuse_pressure", "lifecycle_reexecution_pressure", "cross_object_contamination_pressure"}
    result["semantic_violation_emergence"] = pressure_type in {"error_reentry_pressure", "lifecycle_reexecution_pressure", "stack_depth_pressure"}
    result["classification"] = "semantic_observation"
    return result
