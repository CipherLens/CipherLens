"""Normalize declared acquisition records into a structured execution trace."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import ObservationStatus, PROCESS_EVIDENCE_TYPES, REGISTRY_VERSION, SCHEMA_VERSIONS, SEMANTIC_EVIDENCE_TYPES, ValuePresence
from execution_model.registry import validate_artifact_or_raise


def _semantic_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(item.get(key) for key in ("contract_observable_ref", "observation_binding_ref", "subject_ref", "identity_group_ref", "operation_ref", "phase", "correlation_group_ref"))


def _matches_value(value: Any, value_type: str) -> bool:
    if value_type in {"integer", "duration"}: return type(value) is int
    if value_type == "boolean": return type(value) is bool
    if value_type in {"enum", "outcome", "state", "event", "bytes"}: return isinstance(value, str)
    return False


def build_structured_trace(
    witness: Mapping[str, Any], run_record: Mapping[str, Any], merge: Mapping[str, Any],
    candidate_binding: Mapping[str, Any], contract: Mapping[str, Any], source_map: Mapping[str, Any],
    acquisitions: Sequence[Mapping[str, Any]], process_evidence: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    if witness.get("status") == "INVALID_WITNESS":
        raise ValueError("INVALID_WITNESS cannot form StructuredExecutionTrace")
    lineage = (
        (witness.get("run_record_ref"), run_record.get("run_record_id"), "RunRecord ref"),
        (witness.get("run_record_digest"), artifact_digest(run_record), "RunRecord digest"),
        (witness.get("merge_ref"), merge.get("merge_id"), "Merge ref"),
        (witness.get("candidate_binding_ref"), candidate_binding.get("binding_id"), "CandidateBinding ref"),
        (witness.get("contract_ref"), f"contract:{contract.get('contract_id')}", "Contract ref"),
        (witness.get("source_map_ref"), source_map.get("source_map_id"), "SourceMap ref"),
    )
    mismatch = [name for actual, expected, name in lineage if actual != expected]
    if mismatch:
        raise ValueError("trace lineage mismatch: " + ", ".join(mismatch))
    captures = {x["capture_binding_id"]: x for x in merge.get("observation_capture_bindings", [])}
    bindings = {x["observation_binding_id"]: x for x in candidate_binding.get("observation_bindings", [])}
    map_records = {x["capture_binding_ref"]: x for x in source_map.get("observation_capture_records", [])}
    identities = {subject: item["identity_group_ref"] for item in merge.get("identity_realizations", []) for subject in item.get("subject_binding_refs", [])}
    observations: list[dict[str, Any]] = []
    for index, acquisition in enumerate(acquisitions):
        capture_ref = str(acquisition.get("capture_binding_ref") or "")
        capture = captures.get(capture_ref)
        if capture is None or capture_ref not in map_records:
            raise ValueError(f"undeclared acquisition capture: {capture_ref}")
        binding = bindings.get(capture["observation_binding_ref"])
        if binding is None:
            raise ValueError("Merge capture does not resolve to CandidateBinding observation")
        status = str(acquisition.get("status") or "ACQUISITION_FAILED")
        value_presence = str(acquisition.get("value_presence") or "NONE")
        if status not in {x.value for x in ObservationStatus} or value_presence not in {x.value for x in ValuePresence}:
            raise ValueError("unknown observation/value status")
        if status == "OBSERVED_ABSENCE" and not (acquisition.get("channel_active") is True and acquisition.get("phase_reached") is True):
            raise ValueError("OBSERVED_ABSENCE requires active channel and reached phase")
        value = acquisition.get("value")
        if status == "PRESENT":
            if value_presence == "VALUE" and not _matches_value(value, binding["value_type"]):
                status, value_presence, value = "INVALID_VALUE", "NONE", None
            elif value_presence == "EXPLICIT_NULL" and value is not None:
                status, value_presence, value = "INVALID_VALUE", "NONE", None
            elif value_presence == "ARTIFACT" and not (acquisition.get("value_artifact_ref") and acquisition.get("value_artifact_digest")):
                status, value_presence, value = "INVALID_VALUE", "NONE", None
            elif value_presence == "NONE":
                status = "INVALID_VALUE"
        elif status != "OBSERVED_ABSENCE":
            value_presence, value = "NONE", None
        correlations = capture.get("correlation_refs") or binding.get("correlation_group_refs") or []
        requested_correlation = acquisition.get("correlation_group_ref")
        if requested_correlation is not None and requested_correlation not in correlations:
            raise ValueError("acquisition correlation is not declared by Merge/CandidateBinding")
        requested_identity = acquisition.get("identity_group_ref")
        declared_identity = identities.get(capture["target_subject_binding_ref"], "")
        if requested_identity is not None and requested_identity != declared_identity:
            raise ValueError("acquisition identity is not declared by Merge")
        observations.append({
            "observation_id": f"trace-observation:{index:04d}",
            "contract_observable_ref": capture["contract_observable_ref"], "observation_binding_ref": capture["observation_binding_ref"],
            "capture_binding_ref": capture_ref, "source_map_record_ref": map_records[capture_ref]["record_id"],
            "semantic_role": binding["observable_role"], "subject_ref": capture["target_subject_binding_ref"],
            "identity_group_ref": declared_identity,
            "operation_ref": capture["target_operation_binding_ref"], "phase": capture["phase"],
            "correlation_group_ref": str(acquisition.get("correlation_group_ref") or (correlations[0] if correlations else "")),
            "status": status, "value_presence": value_presence, "value": value,
            "value_artifact_ref": acquisition.get("value_artifact_ref"), "value_artifact_digest": acquisition.get("value_artifact_digest"),
            "evidence_refs": list(acquisition.get("evidence_refs") or []), "sequence_index": int(acquisition.get("sequence_index", index)),
        })
        if observations[-1]["semantic_role"] not in SEMANTIC_EVIDENCE_TYPES:
            raise ValueError("unsupported semantic evidence type")
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in observations: grouped[_semantic_key(item)].append(item)
    conflicts: list[str] = [x["observation_id"] for x in observations if x["status"] == "CONFLICTING_EVIDENCE"]
    for items in grouped.values():
        signatures = {(x["status"], x["value_presence"], repr(x["value"]), x["value_artifact_digest"]) for x in items}
        if len(signatures) > 1:
            for item in items:
                conflicts.append(item["observation_id"]); item["status"] = "CONFLICTING_EVIDENCE"; item["value_presence"] = "NONE"; item["value"] = None
    proc = []
    for index, source in enumerate(process_evidence):
        item = dict(source)
        if item.get("evidence_type") not in PROCESS_EVIDENCE_TYPES: raise ValueError("unsupported process evidence type")
        item.setdefault("evidence_id", f"process-evidence:{index:04d}"); proc.append(item)
    ordered = sorted(observations, key=lambda x: x["sequence_index"])
    document = identify({
        "schema_version": SCHEMA_VERSIONS["trace"], "trace_id": "pending",
        "witness_ref": witness["witness_id"], "witness_digest": artifact_digest(witness),
        "run_record_ref": run_record["run_record_id"], "run_record_digest": artifact_digest(run_record),
        "merge_ref": merge["merge_id"], "merge_digest": witness["merge_digest"],
        "candidate_binding_ref": candidate_binding["binding_id"], "candidate_binding_digest": witness["candidate_binding_digest"],
        "contract_ref": witness["contract_ref"], "contract_digest": witness["contract_digest"],
        "semantic_observations": observations, "process_evidence": proc,
        "execution_sequence": [x["observation_id"] for x in ordered],
        "correlation_groups": sorted({x["correlation_group_ref"] for x in observations if x["correlation_group_ref"]}),
        "ordering_edges": [[a["observation_id"], b["observation_id"]] for a, b in zip(ordered, ordered[1:])],
        "integrity_summary": {"status": "CONFLICTING" if conflicts else "VALID", "reason_codes": ["TRACE_EVIDENCE_CONFLICT"] if conflicts else ["TRACE_NORMALIZED"], "conflicting_observation_refs": sorted(conflicts)},
        "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document)
    return document
