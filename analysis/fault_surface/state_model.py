"""Lifecycle state modeling for execution graphs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any


STATE_RULES = {
    "allocated": ("new", "create", "init", "setup", "import", "parse", "load"),
    "active": ("update", "sign", "verify", "encrypt", "decrypt", "read", "write", "finish", "final"),
    "error": ("fail", "error", "invalid", "reject"),
    "released": ("free", "destroy", "cleanup", "reset", "abort", "close"),
}


def build_state_model(execution_graph: Mapping[str, Any]) -> dict[str, Any]:
    """Construct a generic lifecycle model from an execution graph."""

    object_states: dict[str, list[dict[str, Any]]] = defaultdict(list)
    global_states: list[dict[str, Any]] = []

    for node in execution_graph.get("nodes", []):
        api = str(node.get("api", ""))
        state = _state_for_api(api)
        object_refs = node.get("object_refs") or ["global_context"]
        event = {
            "node_id": node.get("node_id"),
            "api": api,
            "phase": node.get("phase"),
            "state_after": state,
        }
        global_states.append(event)
        for ref in object_refs:
            object_states[str(ref)].append(event)

    state_nodes = []
    transitions = []
    for object_id, events in sorted(object_states.items()):
        previous = "uninitialized"
        for index, event in enumerate(events):
            state_id = f"{object_id}:{index:03d}:{event['state_after']}"
            state_nodes.append(
                {
                    "state_id": state_id,
                    "object_id": object_id,
                    "api": event["api"],
                    "node_id": event["node_id"],
                    "state_before": previous,
                    "state_after": event["state_after"],
                }
            )
            transitions.append(
                {
                    "transition_id": f"{object_id}:{index:03d}",
                    "object_id": object_id,
                    "from_state": previous,
                    "to_state": event["state_after"],
                    "via_node": event["node_id"],
                    "via_api": event["api"],
                    "illegal_transition": _illegal_transition(previous, event["state_after"]),
                    "error_transition": event["state_after"] == "error" or previous == "error",
                }
            )
            previous = event["state_after"]

    return {
        "schema": "fault_surface_state_model_v1",
        "seed_id": execution_graph.get("seed_id"),
        "family": execution_graph.get("family"),
        "target_libraries": execution_graph.get("target_libraries", []),
        "state_node_count": len(state_nodes),
        "transition_count": len(transitions),
        "object_count": len(object_states),
        "objects": sorted(object_states),
        "state_nodes": state_nodes,
        "transitions": transitions,
        "illegal_transition_count": sum(1 for item in transitions if item.get("illegal_transition")),
        "error_transition_count": sum(1 for item in transitions if item.get("error_transition")),
        "global_trace": global_states,
        "model_status": "ok" if state_nodes else "empty_graph",
    }


def _state_for_api(api: str) -> str:
    lower = api.lower()
    for state, tokens in STATE_RULES.items():
        if any(token in lower for token in tokens):
            return state
    return "active"


def _illegal_transition(previous: str, current: str) -> bool:
    if previous == "released" and current in {"active", "error"}:
        return True
    if previous == "error" and current == "active":
        return True
    return False
