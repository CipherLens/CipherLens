"""Control-plane planner for graph-driven fault-surface exploration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class GraphFaultSurfaceController:
    """Convert semantic graph weights into execution-control plans."""

    schema = "graph_fault_surface_controller_v1"

    def plan(
        self,
        graph_bundle: Mapping[str, Any],
        weighted_paths_bundle: Mapping[str, Any] | None = None,
        semantic_divergence_points: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        graph = _graph(graph_bundle)
        nodes = [node for node in graph.get("nodes", []) if isinstance(node, Mapping)]
        edges = [edge for edge in graph.get("edges", []) if isinstance(edge, Mapping)]
        paths = _paths(weighted_paths_bundle, nodes, edges)
        semantic_points = _points(semantic_divergence_points)
        prioritized_paths = _prioritized_paths(paths, edges, semantic_points)
        target_selection = _execution_target_selection(nodes, prioritized_paths)
        mutation_plan = {
            "schema": "graph_driven_mutation_plan_v1",
            "mode": "graph_control_plane_only",
            "high_weight_edges_drive_mutation_priority": True,
            "divergence_nodes_drive_oracle_emphasis": True,
            "lifecycle_edges_drive_state_pressure_points": True,
            "mutation_executed": False,
            "items": [
                {
                    "plan_id": f"graph_mutation_plan_{index:03d}",
                    "path_id": path.get("path_id"),
                    "priority": path.get("priority"),
                    "strategy_hint": _strategy_hint(path),
                    "oracle_emphasis": _oracle_emphasis(path),
                    "state_pressure_injection_point": _state_pressure_point(path),
                }
                for index, path in enumerate(prioritized_paths)
            ],
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "graph_driven_mutation_plan": mutation_plan,
            "prioritized_fault_paths": {
                "schema": "prioritized_fault_paths_v1",
                "paths": prioritized_paths,
                "candidate_queue_written": False,
            },
            "execution_target_selection": target_selection,
            "candidate_queue_written": False,
        }


def plan(
    graph_bundle: Mapping[str, Any],
    weighted_paths_bundle: Mapping[str, Any] | None = None,
    semantic_divergence_points: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan graph-driven fault-surface controls."""

    return GraphFaultSurfaceController().plan(graph_bundle, weighted_paths_bundle, semantic_divergence_points)


def _graph(graph_bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("enriched_graph", "api_semantic_graph_v2"):
        value = graph_bundle.get(key)
        if isinstance(value, Mapping):
            return value
    return graph_bundle if isinstance(graph_bundle.get("nodes"), list) else {}


def _paths(
    weighted_paths_bundle: Mapping[str, Any] | None,
    nodes: list[Mapping[str, Any]],
    edges: list[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    if isinstance(weighted_paths_bundle, Mapping):
        value = weighted_paths_bundle.get("paths")
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    if edges:
        return [
            {
                "path_id": f"path_{index:03d}",
                "nodes": [edge.get("from_node"), edge.get("to_node")],
                "edge": edge.get("edge_id"),
                "vulnerability_likelihood_score": edge.get("vulnerability_likelihood_score", 0),
                "misuse_propagation_potential": edge.get("misuse_propagation_potential", 0),
            }
            for index, edge in enumerate(edges)
        ]
    return [
        {
            "path_id": f"path_{index:03d}",
            "nodes": [node.get("node_id")],
            "edge": None,
            "vulnerability_likelihood_score": node.get("vulnerability_likelihood_score", 0),
            "misuse_propagation_potential": node.get("misuse_propagation_potential", 0),
        }
        for index, node in enumerate(nodes)
    ]


def _points(source: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    if not isinstance(source, Mapping):
        return []
    for key in ("points", "breakpoints", "semantic_divergence_points"):
        value = source.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    return []


def _prioritized_paths(
    paths: list[Mapping[str, Any]],
    edges: list[Mapping[str, Any]],
    semantic_points: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    edge_by_id = {edge.get("edge_id"): edge for edge in edges}
    point_bonus = min(20, len(semantic_points) * 5)
    out = []
    for path in paths:
        edge = edge_by_id.get(path.get("edge"), {})
        score = min(
            100,
            int(path.get("vulnerability_likelihood_score", 0) or 0)
            + int(path.get("misuse_propagation_potential", 0) or 0) // 4
            + int(edge.get("cross_library_divergence_strength", 0) or 0) // 4
            + point_bonus,
        )
        out.append(
            {
                **dict(path),
                "priority": score,
                "graph_control_reason": _reason(path, edge),
                "mutation_executed": False,
            }
        )
    out.sort(key=lambda item: item.get("priority", 0), reverse=True)
    return out


def _execution_target_selection(nodes: list[Mapping[str, Any]], paths: list[Mapping[str, Any]]) -> dict[str, Any]:
    node_ids = {node_id for path in paths[:5] for node_id in path.get("nodes", []) if node_id}
    targets = [
        {
            "library": node.get("library"),
            "node_id": node.get("node_id"),
            "selection_reason": "high_priority_graph_path",
        }
        for node in nodes
        if node.get("node_id") in node_ids
    ]
    return {
        "schema": "execution_target_selection_v1",
        "selection_mode": "graph_priority_control_only",
        "targets": targets,
        "execution_invoked": False,
        "candidate_queue_written": False,
    }


def _strategy_hint(path: Mapping[str, Any]) -> str:
    text = " ".join(str(value) for value in path.values())
    if "lifecycle" in text:
        return "state_transition_mutation"
    if "signature" in text or "key_usage" in text:
        return "api_usage_mutation"
    if "error" in text:
        return "error_path_injection"
    return "differential_trigger"


def _oracle_emphasis(path: Mapping[str, Any]) -> list[str]:
    text = " ".join(str(value) for value in path.values())
    emphasis = ["semantic_oracle"]
    if "lifecycle" in text:
        emphasis.append("state_oracle")
    if "crash" in text or "sanitizer" in text:
        emphasis.append("crash_oracle")
    return sorted(dict.fromkeys(emphasis))


def _state_pressure_point(path: Mapping[str, Any]) -> str:
    text = " ".join(str(value) for value in path.values())
    if "lifecycle" in text:
        return "lifecycle_edge"
    if "error" in text:
        return "error_edge"
    return "not_selected"


def _reason(path: Mapping[str, Any], edge: Mapping[str, Any]) -> str:
    if edge.get("cross_library_divergence_strength"):
        return "high_weight_edge_with_cross_library_divergence"
    if path.get("vulnerability_likelihood_score"):
        return "weighted_fault_path"
    return "graph_path_available"
