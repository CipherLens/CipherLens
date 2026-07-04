"""Enrich existing API semantic graphs with prioritization metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class SemanticGraphEnricher:
    """Add likelihood, propagation, and lifecycle sensitivity metadata."""

    schema = "semantic_graph_enricher_v1"

    def enrich(self, base_graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
        graph = _graph(base_graph_bundle)
        nodes = [dict(node) for node in graph.get("nodes", []) if isinstance(node, Mapping)]
        edges = [dict(edge) for edge in graph.get("edges", []) if isinstance(edge, Mapping)]
        enriched_nodes = [_enrich_node(node) for node in nodes]
        enriched_edges = [_enrich_edge(edge) for edge in edges]
        weighted_paths = _weighted_paths(enriched_nodes, enriched_edges)
        enriched_graph = {
            "schema": "enriched_graph_v1",
            "source_schema": graph.get("schema"),
            "seed_id": graph.get("seed_id"),
            "nodes": enriched_nodes,
            "edges": enriched_edges,
            "vulnerability_likelihood_score": _avg(
                node.get("vulnerability_likelihood_score", 0) for node in enriched_nodes
            ),
            "misuse_propagation_potential": _avg(
                edge.get("misuse_propagation_potential", 0) for edge in enriched_edges
            ),
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "enriched_graph": enriched_graph,
            "vulnerability_weighted_paths": {
                "schema": "vulnerability_weighted_paths_v1",
                "paths": weighted_paths,
                "candidate_queue_written": False,
            },
            "candidate_queue_written": False,
        }


def enrich(base_graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Enrich an API semantic graph bundle."""

    return SemanticGraphEnricher().enrich(base_graph_bundle)


def _graph(base_graph_bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    graph = base_graph_bundle.get("api_semantic_graph_v2")
    return graph if isinstance(graph, Mapping) else {}


def _enrich_node(node: Mapping[str, Any]) -> dict[str, Any]:
    relevance = int(node.get("security_relevance_weight", 0) or 0)
    divergence = int(node.get("cross_library_divergence_strength", 0) or 0)
    correlation = int(node.get("exploitability_correlation_score", 0) or 0)
    likelihood = min(100, (relevance + divergence + correlation) // 3)
    tags = list(node.get("lifecycle_sensitivity_tags") or [])
    if likelihood >= 70:
        tags.append("priority_fault_surface")
    return {
        **dict(node),
        "vulnerability_likelihood_score": likelihood,
        "misuse_propagation_potential": min(100, divergence + len(tags) * 5),
        "lifecycle_sensitivity_tags": sorted(dict.fromkeys(tags)),
    }


def _enrich_edge(edge: Mapping[str, Any]) -> dict[str, Any]:
    relevance = int(edge.get("security_relevance_weight", 0) or 0)
    divergence = int(edge.get("cross_library_divergence_strength", 0) or 0)
    correlation = int(edge.get("exploitability_correlation_score", 0) or 0)
    return {
        **dict(edge),
        "vulnerability_likelihood_score": min(100, (relevance + divergence + correlation) // 3),
        "misuse_propagation_potential": min(100, divergence + relevance // 4),
        "lifecycle_sensitivity_tags": ["cross_library_alignment_sensitive"]
        if divergence
        else ["low_divergence_alignment"],
    }


def _weighted_paths(nodes: list[Mapping[str, Any]], edges: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    paths = []
    node_by_id = {node.get("node_id"): node for node in nodes}
    for edge in edges:
        left = node_by_id.get(edge.get("from_node"), {})
        right = node_by_id.get(edge.get("to_node"), {})
        score = _avg(
            [
                left.get("vulnerability_likelihood_score", 0),
                right.get("vulnerability_likelihood_score", 0),
                edge.get("vulnerability_likelihood_score", 0),
            ]
        )
        paths.append(
            {
                "path_id": f"path_{len(paths):03d}",
                "nodes": [edge.get("from_node"), edge.get("to_node")],
                "edge": edge.get("edge_id"),
                "vulnerability_likelihood_score": score,
                "misuse_propagation_potential": edge.get("misuse_propagation_potential", 0),
            }
        )
    paths.sort(key=lambda item: item.get("vulnerability_likelihood_score", 0), reverse=True)
    return paths


def _avg(values: Any) -> int:
    items = [int(value or 0) for value in values]
    if not items:
        return 0
    return sum(items) // len(items)
