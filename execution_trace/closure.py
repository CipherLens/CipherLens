"""Deterministic UNKNOWN evidence closure without semantic mutation."""

from __future__ import annotations

from typing import Any, Mapping

from execution_model.canonical import artifact_digest, identify
from execution_model.model import ClosureRoute, REGISTRY_VERSION, SCHEMA_VERSIONS, UNKNOWN_REASONS
from execution_model.registry import validate_artifact_or_raise


RERUN_REASONS = {"ACQUISITION_FAILED", "PARTIAL_WITNESS"}
INSTRUMENTATION_REASONS = {"INSTRUMENTATION_FAILURE", "OBSERVATION_NOT_REACHED", "TRACE_EVIDENCE_CONFLICT"}
SWITCH_REASONS = {"CHANNEL_UNAVAILABLE", "INCOMPLETE_CORRELATION", "UNSUPPORTED_RELATION_EVALUATOR"}


def route_unknown(reason_codes: list[str], *, semantic_change_required: bool = False, merge_completion_available: bool = False) -> str:
    reasons = set(reason_codes)
    if not reasons or not reasons <= UNKNOWN_REASONS:
        raise ValueError("closure accepts only frozen UNKNOWN reason codes")
    if semantic_change_required or reasons & SWITCH_REASONS:
        return ClosureRoute.WHOLE_BINDING_SWITCH.value
    if merge_completion_available:
        return ClosureRoute.SAME_MERGE_COMPLETION.value
    if reasons & INSTRUMENTATION_REASONS:
        return ClosureRoute.INSTRUMENTATION_REPAIR.value
    return ClosureRoute.SAME_BINDING_RERUN.value


def build_unknown_closure(
    verdict: Mapping[str, Any], *, reason_codes: list[str], missing_evidence: list[str],
    semantic_change_required: bool = False, merge_completion_available: bool = False,
    record_status: str = "PLANNED",
) -> dict[str, Any]:
    if verdict.get("verdict") != "UNKNOWN": raise ValueError("closure requires UNKNOWN Verdict")
    route = route_unknown(reason_codes, semantic_change_required=semantic_change_required, merge_completion_available=merge_completion_available)
    document = identify({
        "schema_version": SCHEMA_VERSIONS["closure"], "closure_id": "pending",
        "verdict_ref": verdict["verdict_id"], "verdict_digest": artifact_digest(verdict),
        "analysis": {"reason_codes": sorted(reason_codes), "missing_evidence": sorted(missing_evidence)},
        "plan": {"route": route, "candidate_binding_mutation_allowed": False, "merge_mutation_allowed": False, "matcher_reentry_required": route == "WHOLE_BINDING_SWITCH"},
        "record": {"status": record_status, "result_artifact_refs": []},
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document); return document
