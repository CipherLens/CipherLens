"""Differential trace analysis for fault-surface observations."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import Any


def analyze_differential_trace(
    seed_context: Mapping[str, Any],
    execution_graph: Mapping[str, Any],
    state_model: Mapping[str, Any],
    mutation_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Compare runtime traces across states, semantics, and libraries."""

    traces = _runtime_traces(seed_context)
    grouped = _group_by_library(traces)
    observations: list[dict[str, Any]] = []

    observations.extend(state_divergence_detector(grouped))
    observations.extend(execution_path_mismatch_detector(grouped))
    observations.extend(silent_failure_detector(grouped))
    observations.extend(_execution_divergence(grouped))
    observations.extend(_semantic_divergence(grouped))
    observations.extend(_cross_library_divergence(grouped))
    divergence_score = _divergence_score(observations, traces)
    instability_score = _instability_score(observations, mutation_plan)
    divergence_report = {
        "schema": "divergence_report_v1",
        "divergence_score": divergence_score,
        "instability_score": instability_score,
        "detectors": [
            "state_divergence_detector",
            "execution_path_mismatch_detector",
            "silent_failure_detector",
            "execution_divergence",
            "semantic_divergence",
            "cross_library_divergence",
        ],
        "observation_count": len(observations),
        "candidate_queue_written": False,
    }

    return {
        "schema": "fault_surface_differential_oracle_v1",
        "seed_id": execution_graph.get("seed_id"),
        "family": execution_graph.get("family"),
        "target_libraries": execution_graph.get("target_libraries", []),
        "trace_count": len(traces),
        "mutation_count": mutation_plan.get("mutation_count", 0),
        "observation_count": len(observations),
        "observations": observations,
        "divergence_score": divergence_score,
        "instability_score": instability_score,
        "divergence_report": divergence_report,
        "candidate_queue_written": False,
        "claim_level": "feature_layer_observation_only",
        "oracle_status": "ok" if traces else "no_runtime_trace_available",
        "state_model_status": state_model.get("model_status"),
    }


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
            results = (
                candidate.get("results")
                or candidate.get("items")
                or candidate.get("run_results")
                or candidate.get("observations")
                or candidate.get("analysis")
            )
            if isinstance(results, list):
                return [dict(item) for item in results if isinstance(item, Mapping)]
    return []


def _group_by_library(traces: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for trace in traces:
        library = trace.get("target_library") or trace.get("library") or trace.get("target") or "unknown"
        grouped[str(library)].append(trace)
    return dict(grouped)


def state_divergence_detector(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = []
    for library, traces in grouped.items():
        states = {str(trace.get("state") or trace.get("exit_class") or trace.get("classification")) for trace in traces}
        if len(states) > 1:
            rows.append(
                {
                    "observation_id": f"state_divergence:{library}",
                    "kind": "state_divergence",
                    "library": library,
                    "states": sorted(states),
                    "classification": "semantic_observation",
                }
            )
    return rows


def execution_path_mismatch_detector(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = []
    summaries: dict[str, list[str]] = {}
    for library, traces in grouped.items():
        paths = [_trace_path(trace) for trace in traces]
        paths = [path for path in paths if path]
        if paths:
            summaries[library] = sorted(set(paths))
        if len(set(paths)) > 1:
            rows.append(
                {
                    "observation_id": f"execution_path_mismatch:{library}",
                    "kind": "execution_path_mismatch",
                    "library": library,
                    "paths": sorted(set(paths)),
                    "classification": "semantic_observation",
                }
            )
    if len({tuple(value) for value in summaries.values()}) > 1:
        rows.append(
            {
                "observation_id": "execution_path_mismatch:cross_library",
                "kind": "execution_path_mismatch",
                "library_summaries": summaries,
                "classification": "semantic_observation",
            }
        )
    return rows


def silent_failure_detector(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = []
    for library, traces in grouped.items():
        for index, trace in enumerate(traces):
            no_crash = not trace.get("crash") and not trace.get("timeout") and not trace.get("signal")
            success_like = trace.get("return_code") in (0, "0", None) or trace.get("run_status") == "run_success"
            inconsistent = _state_inconsistent(trace)
            if no_crash and success_like and inconsistent:
                rows.append(
                    {
                        "observation_id": f"silent_failure:{library}:{index}",
                        "kind": "silent_failure",
                        "library": library,
                        "state_inconsistency": inconsistent,
                        "classification": "semantic_observation",
                    }
                )
    return rows


def _semantic_divergence(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = []
    for library, traces in grouped.items():
        returns = {str(trace.get("return_code") or trace.get("status") or trace.get("psa_sign_status")) for trace in traces}
        if len(returns) > 1:
            rows.append(
                {
                    "observation_id": f"semantic_divergence:{library}",
                    "kind": "semantic_divergence",
                    "library": library,
                    "return_values": sorted(returns),
                    "classification": "semantic_observation",
                }
            )
    return rows


def _execution_divergence(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows = []
    for library, traces in grouped.items():
        execution_signals = {
            str(
                trace.get("exit_class")
                or trace.get("crash")
                or trace.get("timeout")
                or trace.get("sanitizer_signal")
                or trace.get("status")
                or "normal"
            )
            for trace in traces
        }
        if len(execution_signals) > 1:
            rows.append(
                {
                    "observation_id": f"execution_divergence:{library}",
                    "kind": "execution_divergence",
                    "library": library,
                    "execution_signals": sorted(execution_signals),
                    "classification": "semantic_observation",
                }
            )
    return rows


def _cross_library_divergence(grouped: Mapping[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    if len(grouped) < 2:
        return []
    summaries = {}
    for library, traces in grouped.items():
        summaries[library] = sorted(
            {
                str(
                    (
                        trace.get("classification") or "unknown_classification",
                        trace.get("exit_class") or trace.get("run_status") or "unknown_exit",
                        trace.get("return_code") if trace.get("return_code") is not None else trace.get("status"),
                    )
                )
                for trace in traces
            }
        )
    unique = {tuple(value) for value in summaries.values()}
    if len(unique) <= 1:
        return []
    return [
        {
            "observation_id": "cross_library_divergence:runtime_trace",
            "kind": "cross_library_divergence",
            "library_summaries": summaries,
            "classification": "semantic_observation",
        }
    ]


def _trace_path(trace: Mapping[str, Any]) -> str:
    for key in ("executed_apis", "api_path", "path", "call_sequence", "trace_events"):
        value = trace.get(key)
        if isinstance(value, list):
            return " -> ".join(str(item) for item in value)
        if isinstance(value, str):
            return value
    return ""


def _state_inconsistent(trace: Mapping[str, Any]) -> str:
    if trace.get("state_inconsistent") or trace.get("lifecycle_violation"):
        return "explicit_state_inconsistency"
    consumed = trace.get("consumed_length")
    input_len = trace.get("input_len")
    if consumed is not None and input_len is not None:
        try:
            if int(consumed) < int(input_len) and trace.get("accepted_or_rejected") in (1, "1", True, "accepted"):
                return "accepted_with_unconsumed_input"
        except (TypeError, ValueError):
            pass
    if trace.get("cleanup_after_error") and trace.get("return_code") in (0, "0"):
        return "success_after_error_cleanup_path"
    return ""


def _divergence_score(observations: list[dict[str, Any]], traces: list[dict[str, Any]]) -> int:
    if not traces:
        return 0
    weighted = 0
    weights = {
        "state_divergence": 20,
        "execution_path_mismatch": 25,
        "silent_failure": 30,
        "execution_divergence": 20,
        "semantic_divergence": 15,
        "cross_library_divergence": 25,
    }
    for observation in observations:
        weighted += weights.get(str(observation.get("kind")), 10)
    return min(100, weighted)


def _instability_score(observations: list[dict[str, Any]], mutation_plan: Mapping[str, Any]) -> int:
    failure_mutations = int(mutation_plan.get("failure_inducing_mutation_count", 0) or 0)
    mutation_factor = min(50, failure_mutations * 2)
    observation_factor = min(50, len(observations) * 10)
    return min(100, mutation_factor + observation_factor)
