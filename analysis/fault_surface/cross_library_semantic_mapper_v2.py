"""Cross-library mapping for enriched API semantic graphs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


SUPPORTED_LIBRARIES = ("openssl", "mbedtls", "wolfssl", "botan")


class CrossLibrarySemanticMapperV2:
    """Map enriched API graph nodes into library equivalence views."""

    schema = "cross_library_semantic_mapper_v2"

    def map(self, enriched_graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
        graph = _graph(enriched_graph_bundle)
        nodes = [node for node in graph.get("nodes", []) if isinstance(node, Mapping)]
        rows = [_library_row(library, nodes) for library in SUPPORTED_LIBRARIES]
        equivalence_matrix = _equivalence_matrix(rows)
        heatmap = _divergence_heatmap(rows)
        return {
            "schema": self.schema,
            "cross_library_api_mapping": {
                "schema": "cross_library_api_mapping_v1",
                "supported_libraries": list(SUPPORTED_LIBRARIES),
                "rows": rows,
                "candidate_queue_written": False,
            },
            "semantic_equivalence_matrix": equivalence_matrix,
            "divergence_heatmap": heatmap,
            "candidate_queue_written": False,
        }


def map(enriched_graph_bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Map enriched semantic graph across supported libraries."""

    return CrossLibrarySemanticMapperV2().map(enriched_graph_bundle)


def _graph(enriched_graph_bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    graph = enriched_graph_bundle.get("enriched_graph")
    return graph if isinstance(graph, Mapping) else {}


def _library_row(library: str, nodes: list[Mapping[str, Any]]) -> dict[str, Any]:
    matching = [
        node for node in nodes
        if str(node.get("library", "")).split("-", 1)[0].lower() == library
    ]
    if not matching:
        return {
            "library": library,
            "mapped": False,
            "node_ids": [],
            "semantic_weight": 0,
            "divergence_strength": 0,
            "equivalence_status": "missing_node",
        }
    semantic_weight = _avg(node.get("security_relevance_weight", 0) for node in matching)
    divergence_strength = _avg(node.get("cross_library_divergence_strength", 0) for node in matching)
    return {
        "library": library,
        "mapped": True,
        "node_ids": [node.get("node_id") for node in matching],
        "semantic_weight": semantic_weight,
        "divergence_strength": divergence_strength,
        "equivalence_status": "semantically_mapped",
    }


def _equivalence_matrix(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    matrix = []
    for left in rows:
        for right in rows:
            if left.get("library") == right.get("library"):
                continue
            mapped = bool(left.get("mapped") and right.get("mapped"))
            strength_delta = abs(int(left.get("divergence_strength", 0) or 0) - int(right.get("divergence_strength", 0) or 0))
            matrix.append(
                {
                    "from_library": left.get("library"),
                    "to_library": right.get("library"),
                    "mapped": mapped,
                    "semantic_equivalence": "aligned" if mapped and strength_delta <= 20 else "divergent_or_missing",
                    "divergence_delta": strength_delta,
                }
            )
    return {
        "schema": "semantic_equivalence_matrix_v1",
        "rows": matrix,
        "candidate_queue_written": False,
    }


def _divergence_heatmap(rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    cells = []
    for row in rows:
        cells.append(
            {
                "library": row.get("library"),
                "mapped": row.get("mapped"),
                "semantic_weight": row.get("semantic_weight", 0),
                "divergence_strength": row.get("divergence_strength", 0),
                "heat": min(100, int(row.get("semantic_weight", 0) or 0) + int(row.get("divergence_strength", 0) or 0)) // 2,
            }
        )
    return {
        "schema": "divergence_heatmap_v1",
        "cells": cells,
        "candidate_queue_written": False,
    }


def _avg(values: Any) -> int:
    items = [int(value or 0) for value in values]
    if not items:
        return 0
    return sum(items) // len(items)
