"""Canonical graph alignment for cross-library fault-surface analysis."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


CANONICAL_STATE_ORDER = ("INIT", "SIGN", "VERIFY", "ERROR", "FREE")

STATE_TOKENS = {
    "INIT": ("init", "setup", "new", "create", "load", "parse", "import", "decode", "d2i"),
    "SIGN": ("sign", "encrypt", "update", "final", "finish"),
    "VERIFY": ("verify", "decrypt", "check", "read", "consume"),
    "ERROR": ("fail", "error", "invalid", "reject", "abort"),
    "FREE": ("free", "destroy", "cleanup", "reset", "close"),
}


def align_cross_library_graphs(cross_library_graphs: Mapping[str, Any]) -> dict[str, Any]:
    """Align per-library graphs using canonical lifecycle state labels."""

    aligned = []
    for item in cross_library_graphs.get("graphs", []):
        if not isinstance(item, Mapping):
            continue
        library = str(item.get("library", "unknown"))
        graph = item.get("execution_graph") or {}
        nodes = _align_nodes(library, graph)
        transitions = _align_transitions(graph, nodes)
        aligned.append(
            {
                "library": library,
                "library_role": item.get("library_role"),
                "aligned_node_count": len(nodes),
                "aligned_transition_count": len(transitions),
                "canonical_states_present": sorted({node["canonical_state"] for node in nodes}),
                "nodes": nodes,
                "transitions": transitions,
                "runtime_trace_count": item.get("runtime_trace_count", 0),
            }
        )

    report = _alignment_report(cross_library_graphs, aligned)
    return {
        "schema": "cross_library_graph_alignment_v1",
        "seed_id": cross_library_graphs.get("seed_id"),
        "family": cross_library_graphs.get("family"),
        "canonical_state_mapping": list(CANONICAL_STATE_ORDER),
        "aligned_libraries": aligned,
        "graph_alignment_report": report,
        "alignment_status": "ok" if aligned else "no_library_graphs",
    }


def _align_nodes(library: str, graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for index, node in enumerate(graph.get("nodes", [])):
        if not isinstance(node, Mapping):
            continue
        api = str(node.get("api", ""))
        state = _canonical_state(api)
        rows.append(
            {
                "library": library,
                "node_id": node.get("node_id") or f"{library}:node:{index:03d}",
                "api": api,
                "canonical_state": state,
                "phase": node.get("phase"),
                "object_refs": node.get("object_refs", []),
                "error_prone": bool(node.get("error_prone") or state == "ERROR"),
                "divergence_prone": bool(node.get("divergence_prone")),
            }
        )
    return rows


def _align_transitions(graph: Mapping[str, Any], aligned_nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {node["node_id"]: node for node in aligned_nodes}
    rows = []
    for edge in graph.get("transitions", []):
        if not isinstance(edge, Mapping):
            continue
        source = by_id.get(edge.get("from"))
        target = by_id.get(edge.get("to"))
        rows.append(
            {
                "transition_id": edge.get("transition_id"),
                "from": edge.get("from"),
                "to": edge.get("to"),
                "from_state": source.get("canonical_state") if source else "UNKNOWN",
                "to_state": target.get("canonical_state") if target else "UNKNOWN",
                "error_path": bool(edge.get("error_transition")),
                "illegal_edge": bool(edge.get("illegal_edge")),
            }
        )
    return rows


def _canonical_state(api: str) -> str:
    lower = api.lower()
    for state, tokens in STATE_TOKENS.items():
        if any(token in lower for token in tokens):
            return state
    return "VERIFY"


def _alignment_report(cross_library_graphs: Mapping[str, Any], aligned: list[dict[str, Any]]) -> dict[str, Any]:
    missing_states = {}
    for item in aligned:
        present = set(item.get("canonical_states_present", []))
        missing_states[item["library"]] = [state for state in CANONICAL_STATE_ORDER if state not in present]
    return {
        "schema": "graph_alignment_report_v1",
        "seed_id": cross_library_graphs.get("seed_id"),
        "family": cross_library_graphs.get("family"),
        "library_count": len(aligned),
        "canonical_state_mapping": list(CANONICAL_STATE_ORDER),
        "missing_canonical_states_by_library": missing_states,
        "alignment_status": "ok" if aligned else "no_library_graphs",
    }
