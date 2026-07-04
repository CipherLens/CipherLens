"""Template-layer mutation injection planning from failure patterns."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


INJECTION_BY_PATTERN = {
    "unstable_transition": "invalid_transition_forcing",
    "error_recovery_path": "error_state_chaining_injection",
    "lifecycle_boundary": "lifecycle_violation_injection",
    "cross_object_contamination_point": "cross_library_mismatch_amplification",
}


def build_template_mutation_injections(
    selected_patterns: Mapping[str, Any],
    mutation_bias_profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Create Template Layer mutation injection specs without rendering cases."""

    patterns = selected_patterns.get("selected_failure_patterns", [])
    injections = []
    for index, pattern in enumerate(patterns if isinstance(patterns, list) else []):
        if not isinstance(pattern, Mapping):
            continue
        pattern_kind = str(pattern.get("pattern_kind", "unstable_transition"))
        injection_kind = INJECTION_BY_PATTERN.get(pattern_kind, "invalid_transition_forcing")
        injections.append(
            {
                "injection_id": f"template_failure_injection_{index:03d}",
                "source_pattern_id": pattern.get("pattern_id"),
                "injection_kind": injection_kind,
                "template_layer_position": "before_rendering",
                "mutation_scope": "execution_template",
                "input_mutation": False,
                "failure_inducing": True,
                "bias_weight": _weight_for_injection(injection_kind, mutation_bias_profile),
                "requires_rendering_layer": True,
                "requires_execution_layer": True,
                "candidate_queue_written": False,
            }
        )
    return {
        "schema": "template_mutation_injection_plan_v1",
        "injection_count": len(injections),
        "injections": injections,
        "pipeline_path": [
            "oracle_layer",
            "fault_trigger_bridge",
            "template_layer",
            "rendering_layer",
            "execution_layer",
            "oracle_layer",
        ],
        "plan_status": "ok" if injections else "no_template_mutations_selected",
        "candidate_queue_written": False,
    }


def _weight_for_injection(injection_kind: str, mutation_bias_profile: Mapping[str, Any]) -> int:
    weights = mutation_bias_profile.get("strategy_weights") or {}
    if not isinstance(weights, Mapping):
        return 1
    mapping = {
        "lifecycle_violation_injection": "lifecycle_violation_injection",
        "error_state_chaining_injection": "error_state_continuation_injection",
        "invalid_transition_forcing": "invalid_transition_chaining",
        "cross_library_mismatch_amplification": "cross_object_state_bleeding",
    }
    return int(weights.get(mapping.get(injection_kind, ""), 1) or 1)
