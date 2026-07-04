"""Fault Trigger Bridge v5 for oracle-to-template mutation handoff."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.failure_pattern_selector import select_failure_patterns
from analysis.fault_surface.template_mutation_injector import build_template_mutation_injections


class FaultTriggerBridge:
    """Translate oracle divergence observations into template mutation intent."""

    schema = "fault_trigger_bridge_v5"

    def process(self, oracle_output: Mapping[str, Any]) -> dict[str, Any]:
        selected_patterns = select_failure_patterns(oracle_output)
        mutation_bias_profile = _mutation_bias_profile(oracle_output, selected_patterns)
        template_injections = build_template_mutation_injections(selected_patterns, mutation_bias_profile)
        failure_trigger_candidates = _failure_trigger_candidates(selected_patterns, template_injections)
        report = {
            "schema": "fault_trigger_report_v1",
            "bridge_schema": self.schema,
            "pipeline_path": [
                "oracle_layer",
                "fault_trigger_bridge",
                "template_layer",
                "rendering_layer",
                "execution_layer",
            ],
            "oracle_signal_consumed": True,
            "direct_candidate_queue_write_allowed": False,
            "candidate_queue_written": False,
            "selected_failure_pattern_count": selected_patterns.get("selected_failure_pattern_count", 0),
            "failure_trigger_candidate_count": failure_trigger_candidates.get("trigger_candidate_count", 0),
            "template_injection_count": template_injections.get("injection_count", 0),
            "status": "ok" if template_injections.get("injection_count", 0) else "no_triggerable_failure_pattern",
        }
        return {
            "schema": self.schema,
            "failure_trigger_candidates": failure_trigger_candidates,
            "mutation_bias_profile": mutation_bias_profile,
            "selected_failure_patterns": selected_patterns,
            "template_mutation_injection_plan": template_injections,
            "fault_trigger_report": report,
            "report_payloads": {
                "failure_trigger_candidates.yaml": failure_trigger_candidates,
                "mutation_bias_profile.yaml": mutation_bias_profile,
                "fault_trigger_report.yaml": report,
            },
            "candidate_queue_written": False,
            "claim_level": "trigger_bridge_planning_only",
        }


def process(oracle_output: Mapping[str, Any]) -> dict[str, Any]:
    """Process oracle output through the bridge."""

    return FaultTriggerBridge().process(oracle_output)


def _mutation_bias_profile(
    oracle_output: Mapping[str, Any],
    selected_patterns: Mapping[str, Any],
) -> dict[str, Any]:
    report = oracle_output.get("cross_library_divergence_report") or oracle_output
    feedback_loop = oracle_output.get("mutation_feedback_loop") or {}
    weights = {}
    if isinstance(feedback_loop, Mapping):
        weights = feedback_loop.get("strategy_weights") or {}
    if not isinstance(weights, Mapping) or not weights:
        weights = _weights_from_scores(report)
    focus = _focus_from_patterns(selected_patterns)
    return {
        "schema": "mutation_bias_profile_v1",
        "source": "oracle_layer_cross_library_divergence",
        "divergence_score": _score(report, "divergence_score"),
        "mismatch_score": _score(report, "mismatch_score"),
        "instability_score": _score(report, "instability_score"),
        "focus_bias": focus,
        "strategy_weights": dict(weights),
        "template_layer_target": True,
        "execution_layer_target": True,
        "candidate_queue_written": False,
    }


def _failure_trigger_candidates(
    selected_patterns: Mapping[str, Any],
    template_injections: Mapping[str, Any],
) -> dict[str, Any]:
    injections = template_injections.get("injections", [])
    rows = []
    for index, injection in enumerate(injections if isinstance(injections, list) else []):
        if not isinstance(injection, Mapping):
            continue
        rows.append(
            {
                "trigger_id": f"failure_trigger_{index:03d}",
                "source_pattern_id": injection.get("source_pattern_id"),
                "injection_kind": injection.get("injection_kind"),
                "next_layer": "template_layer",
                "then_layers": ["rendering_layer", "execution_layer", "oracle_layer"],
                "failure_inducing": True,
                "candidate_queue_written": False,
            }
        )
    return {
        "schema": "failure_trigger_candidates_v1",
        "trigger_candidate_count": len(rows),
        "triggers": rows,
        "selected_failure_pattern_count": selected_patterns.get("selected_failure_pattern_count", 0),
        "candidate_queue_written": False,
    }


def _weights_from_scores(report: Mapping[str, Any]) -> dict[str, int]:
    divergence = _score(report, "divergence_score")
    mismatch = _score(report, "mismatch_score")
    instability = _score(report, "instability_score")
    return {
        "lifecycle_violation_injection": 1 + divergence // 25,
        "invalid_transition_chaining": 1 + divergence // 30,
        "reuse_after_free_simulation": 1 + instability // 30,
        "error_state_continuation_injection": 1 + instability // 25,
        "cross_object_state_bleeding": 1 + mismatch // 30,
    }


def _focus_from_patterns(selected_patterns: Mapping[str, Any]) -> list[str]:
    focus = []
    mapping = {
        "unstable_transition": "invalid_transition_chaining",
        "error_recovery_path": "error_state_continuation_injection",
        "lifecycle_boundary": "lifecycle_violation_injection",
        "cross_object_contamination_point": "cross_object_state_bleeding",
    }
    for pattern in selected_patterns.get("selected_failure_patterns", []):
        if isinstance(pattern, Mapping):
            focus.append(mapping.get(str(pattern.get("pattern_kind")), "invalid_transition_chaining"))
    return list(dict.fromkeys(focus))


def _score(report: Mapping[str, Any], key: str) -> int:
    try:
        return int(report.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0
