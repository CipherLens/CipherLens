"""Adapter from graph control outputs to existing execution-plan patches."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class GraphExecutionAdapter:
    """Translate graph plans into render/execution/oracle patch payloads."""

    schema = "graph_execution_adapter_v1"

    def apply(self, graph_outputs: Mapping[str, Any]) -> dict[str, Any]:
        render_patch = build_render_plan_patch(graph_outputs)
        execution_patch = build_execution_plan_patch(graph_outputs)
        oracle_patch = build_oracle_patch(graph_outputs)
        return {
            "schema": self.schema,
            "render_patch": render_patch,
            "execution_patch": execution_patch,
            "oracle_patch": oracle_patch,
            "graph_execution_mapping": _mapping_report(graph_outputs, render_patch, execution_patch, oracle_patch),
            "graph_executes_directly": False,
            "runtime_layer_replaced": False,
            "candidate_queue_written": False,
        }


def apply_graph_to_execution(
    seed_context: Mapping[str, Any],
    graph_outputs: Mapping[str, Any],
) -> dict[str, Any]:
    """Build execution-layer patches from graph outputs."""

    _ = seed_context
    return GraphExecutionAdapter().apply(graph_outputs)


def build_render_plan_patch(graph_outputs: Mapping[str, Any]) -> dict[str, Any]:
    """Map graph priority to render case weighting."""

    mutation_plan = _mutation_plan(graph_outputs)
    paths = _prioritized_paths(graph_outputs)
    modifiers = []
    for item in mutation_plan.get("items", []):
        if not isinstance(item, Mapping):
            continue
        modifiers.append(
            {
                "modifier_id": f"render_modifier_{len(modifiers):03d}",
                "source_plan_id": item.get("plan_id"),
                "path_id": item.get("path_id"),
                "render_case_weight": _weight(item.get("priority", 0)),
                "template_execution_modifier": item.get("strategy_hint"),
            }
        )
    if not modifiers:
        for path in paths:
            modifiers.append(
                {
                    "modifier_id": f"render_modifier_{len(modifiers):03d}",
                    "source_plan_id": None,
                    "path_id": path.get("path_id"),
                    "render_case_weight": _weight(path.get("priority", 0)),
                    "template_execution_modifier": "graph_priority_hint",
                }
            )
    return {
        "schema": "render_plan_patch_v1",
        "patch_type": "render_case_weighting",
        "graph_node_to_template_modifier": True,
        "mutation_priority_to_render_weighting": True,
        "modifiers": modifiers,
        "rendering_system_changed": False,
        "candidate_queue_written": False,
    }


def build_execution_plan_patch(graph_outputs: Mapping[str, Any]) -> dict[str, Any]:
    """Map graph edges and target selection to execution hints."""

    target_selection = _target_selection(graph_outputs)
    paths = _prioritized_paths(graph_outputs)
    ordering_constraints = [
        {
            "constraint_id": f"execution_order_{index:03d}",
            "path_id": path.get("path_id"),
            "nodes": path.get("nodes", []),
            "edge": path.get("edge"),
            "priority": path.get("priority", 0),
        }
        for index, path in enumerate(paths)
    ]
    return {
        "schema": "execution_plan_patch_v1",
        "patch_type": "execution_harness_hints",
        "graph_edge_to_execution_ordering_constraint": True,
        "selected_targets": target_selection.get("targets", []),
        "ordering_constraints": ordering_constraints,
        "execution_pipeline_changed": False,
        "runtime_executed": False,
        "candidate_queue_written": False,
    }


def build_oracle_patch(graph_outputs: Mapping[str, Any]) -> dict[str, Any]:
    """Map graph oracle weights to dispatcher override payload."""

    oracle_profile = _oracle_profile(graph_outputs)
    profile = oracle_profile.get("oracle_weight_profile", {})
    adaptive = oracle_profile.get("adaptive_oracle_config", {})
    return {
        "schema": "oracle_config_patch_v1",
        "patch_type": "oracle_dispatcher_config_override",
        "oracle_weight_to_dispatcher_config": True,
        "weights": profile.get("weights", {}),
        "primary_oracle": adaptive.get("primary_oracle"),
        "oracle_logic_changed": False,
        "candidate_queue_written": False,
    }


def merge_with_existing_pipeline(
    seed_context: Mapping[str, Any],
    execution_patch: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a merged plan view without mutating the existing pipeline."""

    existing = seed_context.get("execution_plan")
    if not isinstance(existing, Mapping):
        existing = {}
    return {
        "schema": "merged_execution_plan_v1",
        "merge_mode": "non_destructive_patch_view",
        "existing_execution_plan": dict(existing),
        "render_plan_patch": execution_patch.get("render_patch", {}),
        "execution_plan_patch": execution_patch.get("execution_patch", {}),
        "oracle_config_patch": execution_patch.get("oracle_patch", {}),
        "execution_pipeline_changed": False,
        "rendering_system_changed": False,
        "oracle_system_changed": False,
        "runtime_executed": False,
        "candidate_queue_written": False,
    }


def _mapping_report(
    graph_outputs: Mapping[str, Any],
    render_patch: Mapping[str, Any],
    execution_patch: Mapping[str, Any],
    oracle_patch: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": "graph_execution_mapping_v1",
        "input_payloads": sorted(graph_outputs.keys()),
        "render_modifier_count": len(render_patch.get("modifiers", [])),
        "execution_constraint_count": len(execution_patch.get("ordering_constraints", [])),
        "oracle_override_count": len(oracle_patch.get("weights", {})),
        "graph_only_modifies_execution_parameters": True,
        "direct_execution_invoked": False,
        "candidate_queue_written": False,
    }


def _mutation_plan(graph_outputs: Mapping[str, Any]) -> Mapping[str, Any]:
    value = graph_outputs.get("graph_driven_mutation_plan")
    if isinstance(value, Mapping):
        return value
    fault_plan = graph_outputs.get("fault_plan")
    if isinstance(fault_plan, Mapping):
        value = fault_plan.get("graph_driven_mutation_plan")
        if isinstance(value, Mapping):
            return value
    return {}


def _prioritized_paths(graph_outputs: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    value = graph_outputs.get("prioritized_fault_paths")
    if isinstance(value, Mapping) and isinstance(value.get("paths"), list):
        return [item for item in value["paths"] if isinstance(item, Mapping)]
    fault_plan = graph_outputs.get("fault_plan")
    if isinstance(fault_plan, Mapping):
        value = fault_plan.get("prioritized_fault_paths")
        if isinstance(value, Mapping) and isinstance(value.get("paths"), list):
            return [item for item in value["paths"] if isinstance(item, Mapping)]
    return []


def _target_selection(graph_outputs: Mapping[str, Any]) -> Mapping[str, Any]:
    value = graph_outputs.get("execution_target_selection")
    if isinstance(value, Mapping):
        return value
    fault_plan = graph_outputs.get("fault_plan")
    if isinstance(fault_plan, Mapping):
        value = fault_plan.get("execution_target_selection")
        if isinstance(value, Mapping):
            return value
    return {}


def _oracle_profile(graph_outputs: Mapping[str, Any]) -> Mapping[str, Any]:
    value = graph_outputs.get("oracle_profile")
    if isinstance(value, Mapping):
        return value
    return graph_outputs if isinstance(graph_outputs.get("oracle_weight_profile"), Mapping) else {}


def _weight(priority: Any) -> int:
    return max(1, min(10, int(priority or 0) // 10 or 1))
