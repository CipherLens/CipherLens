"""Graph-driven oracle weighting profile generation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


BASE_WEIGHTS = {
    "semantic_oracle": 1.0,
    "state_oracle": 1.0,
    "crash_oracle": 1.0,
    "sanitizer_oracle": 1.0,
}


class GraphOracleReweighter:
    """Adjust oracle emphasis from enriched graph metadata."""

    schema = "graph_oracle_reweighter_v1"

    def reweight(self, graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
        graph = _graph(graph_bundle)
        nodes = [node for node in graph.get("nodes", []) if isinstance(node, Mapping)]
        edges = [edge for edge in graph.get("edges", []) if isinstance(edge, Mapping)]
        weights = dict(BASE_WEIGHTS)
        semantic_boost = _semantic_boost(nodes, edges)
        state_boost = _state_boost(nodes, edges)
        crash_boost = _crash_boost(nodes, edges)
        weights["semantic_oracle"] += semantic_boost
        weights["state_oracle"] += state_boost
        weights["crash_oracle"] += crash_boost
        weights["sanitizer_oracle"] += crash_boost
        profile = {
            "schema": "oracle_weight_profile_v1",
            "weights": weights,
            "semantic_divergence_edge_boost": semantic_boost,
            "lifecycle_instability_node_boost": state_boost,
            "crash_prone_path_boost": crash_boost,
            "candidate_queue_written": False,
        }
        adaptive = {
            "schema": "adaptive_oracle_config_v1",
            "oracle_weight_profile": weights,
            "primary_oracle": max(weights, key=weights.get),
            "config_mode": "graph_control_plane_only",
            "oracle_logic_changed": False,
            "runtime_executed": False,
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "oracle_weight_profile": profile,
            "adaptive_oracle_config": adaptive,
            "candidate_queue_written": False,
        }


def reweight(graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Build graph-driven oracle weight profile."""

    return GraphOracleReweighter().reweight(graph_bundle)


def _graph(graph_bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("enriched_graph", "api_semantic_graph_v2"):
        value = graph_bundle.get(key)
        if isinstance(value, Mapping):
            return value
    return graph_bundle if isinstance(graph_bundle.get("nodes"), list) else {}


def _semantic_boost(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> float:
    edge_strength = sum(int(edge.get("cross_library_divergence_strength", 0) or 0) for edge in edges)
    node_strength = sum(int(node.get("cross_library_divergence_strength", 0) or 0) for node in nodes)
    return round(min(3.0, (edge_strength + node_strength) / 200), 2)


def _state_boost(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> float:
    tagged = 0
    for item in list(nodes) + list(edges):
        tags = " ".join(str(tag) for tag in item.get("lifecycle_sensitivity_tags", []))
        if "lifecycle" in tags or "state" in tags:
            tagged += 1
    return round(min(3.0, tagged * 0.5), 2)


def _crash_boost(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> float:
    tagged = 0
    for item in list(nodes) + list(edges):
        text = " ".join(str(value) for value in item.values())
        if "crash" in text or "sanitizer" in text:
            tagged += 1
    return round(min(2.0, tagged * 0.5), 2)
