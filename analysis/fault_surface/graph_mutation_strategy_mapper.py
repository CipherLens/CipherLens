"""Map graph nodes and edges to mutation strategies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class GraphMutationStrategyMapper:
    """Create graph-guided mutation strategy maps without executing them."""

    schema = "graph_mutation_strategy_mapper_v1"

    def map(self, graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
        graph = _graph(graph_bundle)
        nodes = [node for node in graph.get("nodes", []) if isinstance(node, Mapping)]
        edges = [edge for edge in graph.get("edges", []) if isinstance(edge, Mapping)]
        node_items = [_node_strategy(node) for node in nodes]
        edge_items = [_edge_strategy(edge) for edge in edges]
        queue = sorted(
            node_items + edge_items,
            key=lambda item: item.get("priority", 0),
            reverse=True,
        )
        return {
            "schema": self.schema,
            "mutation_strategy_map": {
                "schema": "mutation_strategy_map_v1",
                "node_strategies": node_items,
                "edge_strategies": edge_items,
                "mutation_executed": False,
                "candidate_queue_written": False,
            },
            "graph_guided_mutation_queue": {
                "schema": "graph_guided_mutation_queue_v1",
                "queue": queue,
                "queue_count": len(queue),
                "mutation_executed": False,
                "candidate_queue_written": False,
            },
            "candidate_queue_written": False,
        }


def map(graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Map graph elements to strategy hints."""

    return GraphMutationStrategyMapper().map(graph_bundle)


def _graph(graph_bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("enriched_graph", "api_semantic_graph_v2"):
        value = graph_bundle.get(key)
        if isinstance(value, Mapping):
            return value
    return graph_bundle if isinstance(graph_bundle.get("nodes"), list) else {}


def _node_strategy(node: Mapping[str, Any]) -> dict[str, Any]:
    tags = " ".join(str(tag) for tag in node.get("lifecycle_sensitivity_tags", []))
    fields = " ".join(str(field) for field in node.get("observable_fields", []))
    if "lifecycle" in tags:
        strategy = "state_mutation"
    elif "error" in tags or "error" in fields:
        strategy = "error_injection"
    else:
        strategy = "usage_mutation"
    return {
        "item_id": f"strategy_{node.get('node_id')}",
        "source_kind": "api_node",
        "source_id": node.get("node_id"),
        "library": node.get("library"),
        "strategy": strategy,
        "priority": _priority(node),
        "reason": "API node maps to usage/state mutation",
    }


def _edge_strategy(edge: Mapping[str, Any]) -> dict[str, Any]:
    relation = str(edge.get("relation", ""))
    tags = " ".join(str(tag) for tag in edge.get("lifecycle_sensitivity_tags", []))
    if "error" in relation or "error" in tags:
        strategy = "error_injection"
    elif "lifecycle" in relation or "lifecycle" in tags:
        strategy = "state_mutation"
    elif int(edge.get("cross_library_divergence_strength", 0) or 0):
        strategy = "differential_trigger"
    else:
        strategy = "usage_mutation"
    return {
        "item_id": f"strategy_{edge.get('edge_id')}",
        "source_kind": "api_edge",
        "source_id": edge.get("edge_id"),
        "from_node": edge.get("from_node"),
        "to_node": edge.get("to_node"),
        "strategy": strategy,
        "priority": _priority(edge),
        "reason": "graph edge maps to differential/error/state trigger",
    }


def _priority(item: Mapping[str, Any]) -> int:
    return min(
        100,
        int(item.get("vulnerability_likelihood_score", 0) or 0)
        + int(item.get("misuse_propagation_potential", 0) or 0) // 3
        + int(item.get("cross_library_divergence_strength", 0) or 0) // 4,
    )
