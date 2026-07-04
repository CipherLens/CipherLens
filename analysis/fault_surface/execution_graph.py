"""Execution graph extraction for seed/template contexts.

The graph is derived from generic seed, template, adapter, and trace fields.
It models API calls as state nodes and transitions without assuming a specific
library, issue, or family.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any


CALL_FIELD_NAMES = (
    "api_sequence",
    "call_sequence",
    "calls",
    "operations",
    "steps",
    "setup_sequence",
    "trigger_sequence",
    "teardown_sequence",
)

OBJECT_HINT_RE = re.compile(
    r"\b(?P<object>[A-Za-z_][A-Za-z0-9_]*(?:ctx|CTX|key|KEY|cert|CERT|x509|X509|rsa|RSA|pkey|PKEY|handle|HANDLE))\b"
)

ERROR_TOKENS = ("fail", "error", "invalid", "reject", "abort")
RELEASE_TOKENS = ("free", "destroy", "cleanup", "reset", "close")
DIVERGENCE_TOKENS = (
    "parse",
    "decode",
    "d2i",
    "final",
    "finish",
    "verify",
    "sign",
    "decrypt",
    "encrypt",
    "consume",
)


def extract_execution_graph(seed_context: Mapping[str, Any]) -> dict[str, Any]:
    """Build a normalized API execution graph from an existing seed context."""

    calls = _extract_calls(seed_context)
    nodes: list[dict[str, Any]] = []
    transitions: list[dict[str, Any]] = []
    previous_id: str | None = None

    for index, call in enumerate(calls):
        node_id = f"call_{index:03d}"
        api_name = _api_name(call)
        object_refs = _object_refs(call)
        node = {
            "node_id": node_id,
            "kind": "api_call",
            "api": api_name,
            "phase": _phase_for_call(api_name, index, len(calls)),
            "object_refs": object_refs,
            "error_prone": _has_token(api_name, ERROR_TOKENS),
            "divergence_prone": _has_token(api_name, DIVERGENCE_TOKENS),
            "source": call.get("source", "seed_context"),
            "raw": call.get("raw", call),
        }
        nodes.append(node)
        if previous_id is not None:
            previous_node = nodes[-2]
            transitions.append(
                {
                    "transition_id": f"edge_{index - 1:03d}_{index:03d}",
                    "from": previous_id,
                    "to": node_id,
                    "kind": "sequence",
                    "guard": "previous_call_completed",
                    "from_api": previous_node.get("api"),
                    "to_api": node.get("api"),
                    "error_transition": _is_error_transition(previous_node, node),
                    "illegal_edge": _is_illegal_edge(previous_node, node),
                }
            )
        previous_id = node_id

    objects = sorted({ref for node in nodes for ref in node["object_refs"]})
    execution_trace_graph = {
        "nodes": nodes,
        "transitions": transitions,
        "node_count": len(nodes),
        "transition_count": len(transitions),
    }
    error_surface_graph = _error_surface_graph(nodes, transitions)
    return {
        "schema": "fault_surface_execution_graph_v1",
        "seed_id": seed_context.get("seed_id") or seed_context.get("seed_candidate_id"),
        "family": seed_context.get("family") or seed_context.get("framework_family"),
        "target_libraries": _target_libraries(seed_context),
        "node_count": len(nodes),
        "transition_count": len(transitions),
        "object_count": len(objects),
        "objects": objects,
        "nodes": nodes,
        "transitions": transitions,
        "execution_trace_graph": execution_trace_graph,
        "error_surface_graph": error_surface_graph,
        "error_transition_count": error_surface_graph["error_transition_count"],
        "illegal_edge_count": error_surface_graph["illegal_edge_count"],
        "divergence_prone_node_count": error_surface_graph["divergence_prone_node_count"],
        "extraction_status": "ok" if nodes else "no_calls_found",
    }


def _extract_calls(seed_context: Mapping[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for value in _walk(seed_context):
        if isinstance(value, Mapping):
            for field in CALL_FIELD_NAMES:
                if field in value:
                    calls.extend(_normalize_call_list(value[field], field))
            if "api" in value or "function" in value or "call" in value:
                calls.append(_normalize_call(value, "mapping_call"))
        elif isinstance(value, str) and _looks_like_call(value):
            calls.append(_normalize_call(value, "string_scan"))
    return _dedupe_calls(calls)


def _walk(value: Any) -> Iterable[Any]:
    yield value
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _normalize_call_list(value: Any, source: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [_normalize_call(item, source) for item in value]
    if isinstance(value, str):
        return [_normalize_call(part.strip(), source) for part in re.split(r"[;\n]+", value) if part.strip()]
    if isinstance(value, Mapping):
        return [_normalize_call(value, source)]
    return []


def _normalize_call(value: Any, source: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        api = value.get("api") or value.get("function") or value.get("call") or value.get("name") or "unknown_api"
        return {"api": str(api), "source": source, "raw": dict(value)}
    return {"api": str(value).strip(), "source": source, "raw": value}


def _dedupe_calls(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for call in calls:
        key = (_api_name(call), str(call.get("raw")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(call)
    return deduped


def _api_name(call: Mapping[str, Any]) -> str:
    text = str(call.get("api", "unknown_api"))
    match = re.search(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(", text)
    if match:
        return match.group(1)
    return text.split()[0] if text.split() else "unknown_api"


def _object_refs(call: Mapping[str, Any]) -> list[str]:
    raw = str(call.get("raw", "")) + " " + str(call.get("api", ""))
    refs = {match.group("object") for match in OBJECT_HINT_RE.finditer(raw)}
    return sorted(refs)


def _looks_like_call(value: str) -> bool:
    return bool(re.search(r"[A-Za-z_][A-Za-z0-9_:]*\s*\(", value))


def _phase_for_call(api_name: str, index: int, total: int) -> str:
    lower = api_name.lower()
    if any(token in lower for token in ("init", "setup", "create", "new", "import", "parse", "load")):
        return "setup"
    if any(token in lower for token in ("free", "destroy", "cleanup", "reset", "abort")):
        return "teardown"
    if index == 0:
        return "setup"
    if index == total - 1:
        return "teardown"
    return "trigger"


def _has_token(api_name: str, tokens: tuple[str, ...]) -> bool:
    lower = api_name.lower()
    return any(token in lower for token in tokens)


def _is_error_transition(previous_node: Mapping[str, Any], node: Mapping[str, Any]) -> bool:
    return bool(previous_node.get("error_prone") or node.get("error_prone"))


def _is_illegal_edge(previous_node: Mapping[str, Any], node: Mapping[str, Any]) -> bool:
    previous_api = str(previous_node.get("api", ""))
    next_api = str(node.get("api", ""))
    previous_releases = _has_token(previous_api, RELEASE_TOKENS)
    next_uses_state = _has_token(next_api, DIVERGENCE_TOKENS) or node.get("phase") == "trigger"
    return bool(previous_releases and next_uses_state)


def _error_surface_graph(nodes: list[dict[str, Any]], transitions: list[dict[str, Any]]) -> dict[str, Any]:
    error_nodes = [node for node in nodes if node.get("error_prone")]
    divergence_nodes = [node for node in nodes if node.get("divergence_prone")]
    error_transitions = [edge for edge in transitions if edge.get("error_transition")]
    illegal_edges = [edge for edge in transitions if edge.get("illegal_edge")]
    return {
        "schema": "fault_surface_error_surface_graph_v1",
        "error_nodes": error_nodes,
        "divergence_prone_nodes": divergence_nodes,
        "error_transitions": error_transitions,
        "illegal_edges": illegal_edges,
        "error_node_count": len(error_nodes),
        "divergence_prone_node_count": len(divergence_nodes),
        "error_transition_count": len(error_transitions),
        "illegal_edge_count": len(illegal_edges),
    }


def _target_libraries(seed_context: Mapping[str, Any]) -> list[str]:
    targets = seed_context.get("target_libraries") or seed_context.get("targets") or seed_context.get("target_library")
    if isinstance(targets, str):
        return [targets]
    if isinstance(targets, list):
        return [str(item) for item in targets]
    return []
