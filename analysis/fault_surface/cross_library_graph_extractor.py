"""Cross-library graph extraction for fault-surface analysis.

This module derives library-specific graph views from the existing seed
context and base execution graph. It does not execute cases or create drivers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.execution_graph import extract_execution_graph


BASELINE_REFERENCE_LIBRARIES = {"openssl"}


def extract_cross_library_graphs(
    seed_context: Mapping[str, Any],
    execution_graph: Mapping[str, Any],
) -> dict[str, Any]:
    """Build library-specific execution graph views from seed pipeline data."""

    libraries = _target_libraries(seed_context, execution_graph)
    slot_bindings = _slot_bindings_by_library(seed_context)
    traces = _runtime_traces_by_library(seed_context)
    graphs = []

    for library in libraries:
        binding_context = dict(seed_context)
        if library in slot_bindings:
            binding_context["slot_bindings"] = slot_bindings[library]
            graph = extract_execution_graph(binding_context)
            source = "library_specific_slot_binding"
        else:
            graph = _clone_graph_for_library(execution_graph, library)
            source = "base_seed_execution_graph"
        graphs.append(
            {
                "library": library,
                "library_role": "baseline_reference" if _library_key(library) in BASELINE_REFERENCE_LIBRARIES else "comparison_target",
                "graph_source": source,
                "execution_graph": graph,
                "runtime_traces": traces.get(library, []),
                "runtime_trace_count": len(traces.get(library, [])),
            }
        )

    return {
        "schema": "cross_library_execution_graphs_v1",
        "seed_id": execution_graph.get("seed_id") or seed_context.get("seed_id"),
        "family": execution_graph.get("family") or seed_context.get("framework_family"),
        "library_count": len(graphs),
        "libraries": libraries,
        "graphs": graphs,
        "extraction_status": "ok" if graphs else "no_target_libraries",
        "standalone_execution": False,
    }


def _target_libraries(seed_context: Mapping[str, Any], execution_graph: Mapping[str, Any]) -> list[str]:
    values = (
        execution_graph.get("target_libraries")
        or seed_context.get("target_libraries")
        or seed_context.get("targets")
        or seed_context.get("target_library")
        or []
    )
    if isinstance(values, str):
        values = [values]
    libraries = [str(item) for item in values if str(item)]
    return sorted(dict.fromkeys(libraries))


def _slot_bindings_by_library(seed_context: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    bindings = seed_context.get("slot_bindings", [])
    if not isinstance(bindings, list):
        return {}
    rows: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        if not isinstance(binding, Mapping):
            continue
        library = binding.get("target") or binding.get("target_library") or binding.get("library")
        if library:
            rows.setdefault(str(library), []).append(dict(binding))
    return rows


def _runtime_traces_by_library(seed_context: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    traces = _runtime_traces(seed_context)
    rows: dict[str, list[dict[str, Any]]] = {}
    for trace in traces:
        library = trace.get("target_library") or trace.get("library") or trace.get("target")
        if library:
            rows.setdefault(str(library), []).append(trace)
    return rows


def _runtime_traces(seed_context: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = (
        seed_context.get("runtime_traces"),
        seed_context.get("execution_traces"),
        seed_context.get("runtime_results"),
        seed_context.get("run_results"),
    )
    for candidate in candidates:
        if isinstance(candidate, list):
            return [dict(item) for item in candidate if isinstance(item, Mapping)]
        if isinstance(candidate, Mapping):
            for key in ("results", "items", "run_results", "observations", "analysis"):
                value = candidate.get(key)
                if isinstance(value, list):
                    return [dict(item) for item in value if isinstance(item, Mapping)]
    return []


def _clone_graph_for_library(execution_graph: Mapping[str, Any], library: str) -> dict[str, Any]:
    graph = dict(execution_graph)
    graph["target_libraries"] = [library]
    graph["library_specific_view"] = True
    graph["library"] = library
    return graph


def _library_key(library: str) -> str:
    return library.split("-", 1)[0].lower()
