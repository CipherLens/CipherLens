"""Cross-library graph divergence comparison."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def compare_aligned_graphs(alignment: Mapping[str, Any]) -> dict[str, Any]:
    """Compare aligned library graphs for node, transition, and error-path drift."""

    libraries = [item for item in alignment.get("aligned_libraries", []) if isinstance(item, Mapping)]
    node_rows = _node_divergence(libraries)
    transition_rows = _transition_divergence(libraries)
    error_rows = _error_path_divergence(libraries)
    all_rows = node_rows + transition_rows + error_rows

    return {
        "schema": "cross_library_divergence_comparison_v1",
        "seed_id": alignment.get("seed_id"),
        "family": alignment.get("family"),
        "library_count": len(libraries),
        "node_divergence": node_rows,
        "transition_divergence": transition_rows,
        "error_path_divergence": error_rows,
        "node_divergence_count": len(node_rows),
        "transition_divergence_count": len(transition_rows),
        "error_path_divergence_count": len(error_rows),
        "total_divergence_count": len(all_rows),
        "comparison_status": "ok" if libraries else "no_aligned_graphs",
    }


def _node_divergence(libraries: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    signatures = {
        item["library"]: tuple(node.get("canonical_state") for node in item.get("nodes", []))
        for item in libraries
    }
    if len({value for value in signatures.values()}) <= 1:
        return []
    return [
        {
            "kind": "node_divergence",
            "library_signatures": {key: list(value) for key, value in signatures.items()},
            "classification": "semantic_observation",
        }
    ]


def _transition_divergence(libraries: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    signatures = {
        item["library"]: tuple(
            (edge.get("from_state"), edge.get("to_state"))
            for edge in item.get("transitions", [])
        )
        for item in libraries
    }
    if len({value for value in signatures.values()}) <= 1:
        return []
    return [
        {
            "kind": "transition_divergence",
            "library_signatures": {key: [list(pair) for pair in value] for key, value in signatures.items()},
            "classification": "semantic_observation",
        }
    ]


def _error_path_divergence(libraries: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    signatures = {
        item["library"]: (
            sum(1 for edge in item.get("transitions", []) if edge.get("error_path")),
            sum(1 for edge in item.get("transitions", []) if edge.get("illegal_edge")),
            sum(1 for node in item.get("nodes", []) if node.get("error_prone")),
        )
        for item in libraries
    }
    if len({value for value in signatures.values()}) <= 1:
        return []
    return [
        {
            "kind": "error_path_divergence",
            "library_error_path_signatures": {
                key: {
                    "error_transition_count": value[0],
                    "illegal_edge_count": value[1],
                    "error_prone_node_count": value[2],
                }
                for key, value in signatures.items()
            },
            "classification": "semantic_observation",
        }
    ]
