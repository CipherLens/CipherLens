"""Build API semantic graph v2 from final validation artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class APISemanticGraphBuilderV2:
    """Construct an enhanced semantic graph from validation outputs."""

    schema = "api_semantic_graph_builder_v2"

    def build(self, seed_context: Mapping[str, Any]) -> dict[str, Any]:
        verdict = _mapping(seed_context.get("final_security_verdict"))
        unified = _mapping(seed_context.get("unified_runtime_truth"))
        semantic_points = _semantic_points(seed_context)
        nodes = _build_nodes(unified, semantic_points, verdict)
        edges = _build_edges(nodes, semantic_points, verdict)
        graph = {
            "schema": "api_semantic_graph_v2",
            "seed_id": seed_context.get("seed_id") or unified.get("seed_id"),
            "source": "cve_final_validation_outputs",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "security_relevance_weight": _security_relevance_weight(verdict),
            "cross_library_divergence_strength": _divergence_strength(semantic_points),
            "exploitability_correlation_score": _exploitability_correlation(seed_context, verdict),
            "nodes": nodes,
            "edges": edges,
            "candidate_queue_written": False,
        }
        return {
            "schema": self.schema,
            "api_semantic_graph_v2": graph,
            "enhanced_api_nodes": {
                "schema": "enhanced_api_nodes_v1",
                "nodes": nodes,
                "candidate_queue_written": False,
            },
            "enhanced_api_edges": {
                "schema": "enhanced_api_edges_v1",
                "edges": edges,
                "candidate_queue_written": False,
            },
            "candidate_queue_written": False,
        }


def build(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Build API semantic graph v2 from validation outputs."""

    return APISemanticGraphBuilderV2().build(seed_context)


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _semantic_points(seed_context: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    source = seed_context.get("semantic_divergence_points")
    if not isinstance(source, Mapping):
        source = seed_context.get("crypto_semantic_breakpoints")
    if not isinstance(source, Mapping):
        return []
    for key in ("points", "breakpoints", "semantic_divergence_points"):
        value = source.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, Mapping)]
    return []


def _build_nodes(
    unified: Mapping[str, Any],
    semantic_points: list[Mapping[str, Any]],
    verdict: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = [row for row in unified.get("rows", []) if isinstance(row, Mapping)]
    nodes = []
    verdict_weight = _security_relevance_weight(verdict)
    for index, row in enumerate(rows):
        signature = row.get("outcome_signature") if isinstance(row.get("outcome_signature"), Mapping) else {}
        nodes.append(
            {
                "node_id": f"api_node_{index:03d}",
                "library": row.get("library"),
                "authoritative_source": row.get("authoritative_source"),
                "observable_fields": sorted(signature.keys()),
                "security_relevance_weight": verdict_weight,
                "cross_library_divergence_strength": _divergence_strength(semantic_points),
                "exploitability_correlation_score": int(verdict.get("exploitability_score", 0) or 0),
                "lifecycle_sensitivity_tags": _lifecycle_tags(signature, semantic_points),
            }
        )
    return nodes


def _build_edges(
    nodes: list[Mapping[str, Any]],
    semantic_points: list[Mapping[str, Any]],
    verdict: Mapping[str, Any],
) -> list[dict[str, Any]]:
    edges = []
    strength = _divergence_strength(semantic_points)
    for index in range(max(0, len(nodes) - 1)):
        left = nodes[index]
        right = nodes[index + 1]
        edges.append(
            {
                "edge_id": f"api_edge_{index:03d}",
                "from_node": left.get("node_id"),
                "to_node": right.get("node_id"),
                "relation": "cross_library_semantic_alignment",
                "security_relevance_weight": _security_relevance_weight(verdict),
                "cross_library_divergence_strength": strength,
                "exploitability_correlation_score": min(
                    int(left.get("exploitability_correlation_score", 0) or 0),
                    int(right.get("exploitability_correlation_score", 0) or 0),
                ),
            }
        )
    return edges


def _security_relevance_weight(verdict: Mapping[str, Any]) -> int:
    value = str(verdict.get("verdict", ""))
    if value == "CVE_CONFIRMED":
        return 100
    if value == "NON_EXPLOITABLE_INCONSISTENCY":
        return 40
    if value == "INSUFFICIENT_EVIDENCE":
        return 15
    return 0


def _divergence_strength(points: list[Mapping[str, Any]]) -> int:
    if not points:
        return 0
    scores = [int(point.get("score", point.get("semantic_divergence_score", 50)) or 0) for point in points]
    return min(100, sum(scores) // len(scores))


def _exploitability_correlation(seed_context: Mapping[str, Any], verdict: Mapping[str, Any]) -> int:
    score = verdict.get("exploitability_score")
    if score is not None:
        return int(score or 0)
    exploitability = seed_context.get("exploitability")
    if isinstance(exploitability, Mapping):
        return int(exploitability.get("exploitability_score", 0) or 0)
    return 0


def _lifecycle_tags(signature: Mapping[str, Any], semantic_points: list[Mapping[str, Any]]) -> list[str]:
    text = " ".join(str(value) for value in list(signature.values()) + list(semantic_points))
    tags = []
    if "lifecycle" in text:
        tags.append("lifecycle_sensitive")
    if "signature" in text or "verify" in text:
        tags.append("signature_decision_sensitive")
    if "key_usage" in text or "key usage" in text:
        tags.append("key_usage_sensitive")
    return tags or ["semantic_observation"]
