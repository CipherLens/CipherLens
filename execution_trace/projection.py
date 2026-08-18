"""Exact typed Contract.O projection from StructuredExecutionTrace."""

from __future__ import annotations

from typing import Any, Mapping

from execution_model.canonical import artifact_digest, identify, semantic_digest
from execution_model.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise


STATUS_REASONS = {
    "NOT_REACHED": "OBSERVATION_NOT_REACHED", "CHANNEL_UNAVAILABLE": "CHANNEL_UNAVAILABLE",
    "ACQUISITION_FAILED": "ACQUISITION_FAILED", "INVALID_VALUE": "INVALID_VALUE",
    "CONFLICTING_EVIDENCE": "TRACE_EVIDENCE_CONFLICT",
}


def project_contract_evidence(
    contract: Mapping[str, Any], candidate_binding: Mapping[str, Any], merge: Mapping[str, Any],
    source_map: Mapping[str, Any], trace: Mapping[str, Any],
) -> dict[str, Any]:
    lineage = (
        (trace.get("contract_ref"), f"contract:{contract.get('contract_id')}", "Contract ref"),
        (trace.get("candidate_binding_ref"), candidate_binding.get("binding_id"), "CandidateBinding ref"),
        (trace.get("merge_ref"), merge.get("merge_id"), "Merge ref"),
    )
    mismatch = [name for actual, expected, name in lineage if actual != expected]
    if mismatch:
        raise ValueError("projection lineage mismatch: " + ", ".join(mismatch))
    bindings = {x["contract_observable_ref"]: x for x in candidate_binding.get("observation_bindings", [])}
    captures = {x["contract_observable_ref"]: x for x in merge.get("observation_capture_bindings", [])}
    map_records = {x["capture_binding_ref"]: x for x in source_map.get("observation_capture_records", [])}
    by_contract: dict[str, list[dict[str, Any]]] = {}
    for item in trace.get("semantic_observations", []): by_contract.setdefault(item["contract_observable_ref"], []).append(item)
    entries = []
    for declaration in contract["observable_evidence"]["observables"]:
        ref = declaration["observable_id"]; binding = bindings.get(ref); capture = captures.get(ref)
        candidates = by_contract.get(ref, []); exact: list[dict[str, Any]] = []
        if binding and capture and capture.get("capture_binding_id") in map_records:
            exact = [x for x in candidates if x["observation_binding_ref"] == binding["observation_binding_id"] and x["capture_binding_ref"] == capture["capture_binding_id"] and x["semantic_role"] == declaration["semantic_role"] and x["phase"] == capture["phase"] and x["operation_ref"] == capture["target_operation_binding_ref"] and x["subject_ref"] == capture["target_subject_binding_ref"]]
        if not binding or not capture or capture.get("capture_binding_id") not in map_records:
            status, sufficiency, correlation, reason, selected = "CHANNEL_UNAVAILABLE", "INSUFFICIENT", "INVALID", "OBSERVATION_LINEAGE_INCOMPLETE", []
        elif not exact:
            status, sufficiency, correlation, reason, selected = "ACQUISITION_FAILED", "INSUFFICIENT", "INCOMPLETE", "MISSING_REQUIRED_OBSERVABLE", []
        elif any(x["status"] == "CONFLICTING_EVIDENCE" for x in exact) or len({(x["status"], x["value_presence"], repr(x["value"]), x["value_artifact_digest"]) for x in exact}) > 1:
            status, sufficiency, correlation, reason, selected = "CONFLICTING_EVIDENCE", "CONFLICTING", "INVALID", "TRACE_EVIDENCE_CONFLICT", exact
        else:
            selected = exact; status = exact[0]["status"]
            sufficiency = "SUFFICIENT" if status in {"PRESENT", "OBSERVED_ABSENCE"} else "INSUFFICIENT"
            declared_correlations = set(capture.get("correlation_refs") or []) & set(binding.get("correlation_group_refs") or [])
            selected_correlation = exact[0]["correlation_group_ref"]
            if selected_correlation and selected_correlation not in declared_correlations:
                correlation = "INVALID"
            elif selected_correlation:
                correlation = "SATISFIED"
            else:
                correlation = "NOT_APPLICABLE"
            reason = "PROJECTION_SUFFICIENT" if sufficiency == "SUFFICIENT" else STATUS_REASONS.get(status, "MISSING_REQUIRED_OBSERVABLE")
            if correlation == "INVALID":
                reason = "INCOMPLETE_CORRELATION"
        entries.append({
            "contract_observable_ref": ref, "semantic_role": declaration["semantic_role"],
            "observation_binding_ref": binding["observation_binding_id"] if binding else "",
            "merge_capture_ref": capture["capture_binding_id"] if capture else "",
            "source_map_capture_ref": map_records[capture["capture_binding_id"]]["record_id"] if capture and capture["capture_binding_id"] in map_records else "",
            "trace_evidence_refs": [x["observation_id"] for x in selected], "trace_evidence_digests": [semantic_digest(x) for x in selected],
            "observation_status": status, "value_presence": selected[0]["value_presence"] if selected and sufficiency != "CONFLICTING" else "NONE",
            "value": selected[0]["value"] if selected and sufficiency != "CONFLICTING" else None,
            "sufficiency": sufficiency, "correlation_state": correlation,
            "missing_requirements": [] if sufficiency == "SUFFICIENT" else [ref], "reason_code": reason,
        })
    document = identify({
        "schema_version": SCHEMA_VERSIONS["projection"], "projection_id": "pending",
        "trace_ref": trace["trace_id"], "trace_digest": artifact_digest(trace),
        "contract_ref": trace["contract_ref"], "contract_digest": trace["contract_digest"],
        "candidate_binding_ref": candidate_binding["binding_id"], "candidate_binding_digest": trace["candidate_binding_digest"],
        "merge_ref": merge["merge_id"], "merge_digest": trace["merge_digest"],
        "entries": entries, "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document); return document
