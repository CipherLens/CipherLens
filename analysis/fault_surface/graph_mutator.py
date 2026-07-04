"""Fault-surface mutations over lifecycle execution graphs.

These mutations alter execution order and object-state relationships. They do
not mutate raw input bytes and do not create case-specific drivers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


MUTATION_KINDS = (
    "lifecycle_violation_injection",
    "invalid_transition_chaining",
    "reuse_after_free_simulation",
    "error_state_continuation_injection",
    "cross_object_state_bleeding",
)


def build_fault_surface_mutations(
    execution_graph: Mapping[str, Any],
    state_model: Mapping[str, Any],
    *,
    max_mutations: int = 32,
) -> dict[str, Any]:
    """Create a bounded mutation plan from graph/state structure."""

    mutations: list[dict[str, Any]] = []
    transitions = list(state_model.get("transitions", []))
    objects = list(state_model.get("objects", []))
    graph_edges = list(execution_graph.get("transitions", []))
    error_surface_graph = execution_graph.get("error_surface_graph") or {}

    mutations.extend(_lifecycle_violation_injections(transitions))
    mutations.extend(_invalid_transition_chaining(transitions, graph_edges))
    mutations.extend(_reuse_after_free_simulations(transitions))
    mutations.extend(_error_state_continuation_injections(transitions, error_surface_graph))
    mutations.extend(_cross_object_state_bleeding(objects, transitions))

    bounded = mutations[:max_mutations]
    strength_report = _mutation_strength_report(bounded, len(mutations), max_mutations)
    return {
        "schema": "fault_surface_mutation_plan_v1",
        "seed_id": execution_graph.get("seed_id"),
        "family": execution_graph.get("family"),
        "target_libraries": execution_graph.get("target_libraries", []),
        "mutation_scope": "execution_graph",
        "input_mutation": False,
        "parameter_only_mutation": False,
        "semantic_equivalent_transform": False,
        "mutation_strength": "failure_inducing",
        "bounded": True,
        "max_mutations": max_mutations,
        "mutation_count": len(bounded),
        "mutation_kinds": list(MUTATION_KINDS),
        "failure_inducing_mutation_count": sum(1 for item in bounded if item.get("failure_inducing")),
        "mutation_strength_report": strength_report,
        "mutations": bounded,
        "plan_status": "ok" if bounded else "no_state_transitions_available",
    }


def _lifecycle_violation_injections(transitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for transition in transitions:
        rows.append(
            {
                "mutation_id": f"fsm_lifecycle_violate_skip_{transition.get('transition_id')}",
                "kind": "lifecycle_violation_injection",
                "operator": "skip_required_prior_state",
                "target_transition": transition,
                "failure_inducing": True,
                "allowed_invalid_state_transition": True,
                "expected_fault_surface": "missing_required_lifecycle_state",
            }
        )
        rows.append(
            {
                "mutation_id": f"fsm_lifecycle_violate_double_{transition.get('transition_id')}",
                "kind": "lifecycle_violation_injection",
                "operator": "duplicate_non_idempotent_transition",
                "target_transition": transition,
                "failure_inducing": True,
                "allowed_invalid_state_transition": True,
                "expected_fault_surface": "duplicate_lifecycle_transition",
            }
        )
    return rows


def _invalid_transition_chaining(
    transitions: list[dict[str, Any]],
    graph_edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for transition in transitions:
        rows.append(
            {
                "mutation_id": f"fsm_invalid_chain_{transition.get('transition_id')}",
                "kind": "invalid_transition_chaining",
                "operator": "force_transition_without_compatible_source_state",
                "target_transition": transition,
                "forced_from_state": "released" if transition.get("to_state") != "released" else "error",
                "forced_to_state": transition.get("to_state"),
                "failure_inducing": True,
                "allowed_invalid_state_transition": True,
                "expected_fault_surface": "invalid_state_chain_reaches_api",
            }
        )
    for edge in graph_edges:
        if edge.get("illegal_edge"):
            rows.append(
                {
                    "mutation_id": f"fsm_existing_illegal_edge_{edge.get('transition_id')}",
                    "kind": "invalid_transition_chaining",
                    "operator": "amplify_existing_illegal_edge",
                    "target_graph_edge": edge,
                    "failure_inducing": True,
                    "allowed_invalid_state_transition": True,
                    "expected_fault_surface": "existing_illegal_edge_amplified",
                }
            )
    return rows


def _reuse_after_free_simulations(transitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for transition in transitions:
        if transition.get("to_state") != "released":
            continue
        rows.append(
            {
                "mutation_id": f"fsm_reuse_after_release_{transition.get('transition_id')}",
                "kind": "reuse_after_free_simulation",
                "operator": "reuse_object_after_terminal_state",
                "target_transition": transition,
                "failure_inducing": True,
                "allowed_reuse_after_free_pattern": True,
                "expected_fault_surface": "terminal_state_reuse_path",
            }
        )
    return rows


def _error_state_continuation_injections(
    transitions: list[dict[str, Any]],
    error_surface_graph: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for transition in transitions:
        if transition.get("to_state") != "error" and not transition.get("error_transition"):
            continue
        rows.append(
            {
                "mutation_id": f"fsm_error_reuse_{transition.get('transition_id')}",
                "kind": "error_state_continuation_injection",
                "operator": "continue_after_error_without_reset",
                "target_transition": transition,
                "failure_inducing": True,
                "allowed_invalid_state_transition": True,
                "expected_fault_surface": "error_state_continuation_path",
            }
        )
    for node in error_surface_graph.get("error_nodes", []):
        rows.append(
            {
                "mutation_id": f"fsm_error_node_continue_{node.get('node_id')}",
                "kind": "error_state_continuation_injection",
                "operator": "continue_after_error_prone_api",
                "target_node": node,
                "failure_inducing": True,
                "expected_fault_surface": "error_node_continuation_path",
            }
        )
    return rows


def _cross_object_state_bleeding(objects: list[str], transitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(objects) < 2:
        return []
    rows = []
    first, second = objects[0], objects[1]
    for transition in transitions:
        if transition.get("object_id") != first:
            continue
        rows.append(
            {
                "mutation_id": f"fsm_cross_object_bleed_{transition.get('transition_id')}",
                "kind": "cross_object_state_bleeding",
                "operator": "substitute_object_state_carrier",
                "source_object": first,
                "replacement_object": second,
                "target_transition": transition,
                "failure_inducing": True,
                "allowed_cross_object_contamination": True,
                "expected_fault_surface": "wrong_object_state_or_type_reuse",
            }
        )
    return rows


def _mutation_strength_report(
    mutations: list[dict[str, Any]],
    unbounded_count: int,
    max_mutations: int,
) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for mutation in mutations:
        kind = str(mutation.get("kind", "unknown"))
        by_kind[kind] = by_kind.get(kind, 0) + 1
    return {
        "schema": "mutation_strength_report_v1",
        "mutation_strength": "failure_inducing",
        "input_mutation": False,
        "parameter_only_mutation": False,
        "semantic_equivalent_transform": False,
        "max_mutations": max_mutations,
        "unbounded_mutation_count": unbounded_count,
        "selected_mutation_count": len(mutations),
        "failure_inducing_mutation_count": sum(1 for item in mutations if item.get("failure_inducing")),
        "strategies_enabled": list(MUTATION_KINDS),
        "mutation_count_by_kind": by_kind,
    }
