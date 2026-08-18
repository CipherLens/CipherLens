"""Guard-aware deterministic Contract.P relation-instance evaluation."""

from __future__ import annotations

from typing import Any, Mapping

from contract_miner.relation_instance import evaluate_relation_instance_observations
from contract_miner.relations import Observation, RELATION_TYPES
from execution_model.canonical import artifact_digest, identify
from execution_model.model import RELATION_REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise


STATUS_REASON = {
    "NOT_REACHED": "OBSERVATION_NOT_REACHED", "CHANNEL_UNAVAILABLE": "CHANNEL_UNAVAILABLE",
    "ACQUISITION_FAILED": "ACQUISITION_FAILED", "INVALID_VALUE": "INVALID_VALUE",
    "CONFLICTING_EVIDENCE": "TRACE_EVIDENCE_CONFLICT",
}


def _refs(relation: Mapping[str, Any]) -> list[str]:
    return sorted(str(value) for key, value in (relation.get("operands") or {}).items() if key.endswith("_ref") and key != "expected_state_ref")


def _not_evaluable(relation: Mapping[str, Any], reason: str, missing: list[str], invalid: list[str], base: dict[str, Any]) -> dict[str, Any]:
    return _artifact(relation, "NOT_EVALUABLE", reason, missing, invalid, [], {**base, "broken_admissible": False})


def _artifact(relation: Mapping[str, Any], result: str, reason: str, missing: list[str], invalid: list[str], bindings: list[dict[str, Any]], admissibility: dict[str, Any]) -> dict[str, Any]:
    materialized = dict(admissibility)
    context = materialized.pop("_context")
    document = identify({
        "schema_version": SCHEMA_VERSIONS["relation_evaluation"], "evaluation_id": "pending",
        "relation_instance_ref": relation["relation_id"], "relation_type": relation["type"], "criticality": relation["criticality"],
        "contract_ref": context["contract_ref"], "contract_digest": context["contract_digest"],
        "witness_ref": context["witness_ref"], "witness_digest": context["witness_digest"],
        "trace_ref": context["trace_ref"], "trace_digest": context["trace_digest"],
        "projection_refs": context["projection_refs"], "correlation_refs": context["correlation_refs"],
        "evaluator_version": RELATION_REGISTRY_VERSION, "result": result, "reason_code": reason,
        "missing_requirements": missing, "invalid_requirements": invalid,
        "evidence_bindings": bindings, "admissibility": materialized,
    })
    validate_artifact_or_raise(document); return document


def evaluate_relation_instance(
    relation: Mapping[str, Any], contract: Mapping[str, Any], witness: Mapping[str, Any],
    trace: Mapping[str, Any], projection: Mapping[str, Any],
) -> dict[str, Any]:
    refs = _refs(relation); entries = {x["contract_observable_ref"]: x for x in projection["entries"]}
    trace_by_id = {x["observation_id"]: x for x in trace["semantic_observations"]}
    selected = [trace_by_id[eid] for ref in refs for eid in entries.get(ref, {}).get("trace_evidence_refs", []) if eid in trace_by_id]
    correlation_refs = sorted({x["correlation_group_ref"] for x in selected if x["correlation_group_ref"]})
    context = {"contract_ref": witness["contract_ref"], "contract_digest": witness["contract_digest"], "witness_ref": witness["witness_id"], "witness_digest": artifact_digest(witness), "trace_ref": trace["trace_id"], "trace_digest": artifact_digest(trace), "projection_refs": [{"ref": projection["projection_id"], "digest": artifact_digest(projection)}], "correlation_refs": correlation_refs}
    admissibility = {"_context": context, "witness_status": witness["status"], "evidence_complete": True, "phase_reached": True, "channel_valid": True, "subject_valid": True, "identity_valid": True, "correlation_valid": True, "provenance_valid": True}
    lineage = (
        (trace.get("witness_ref"), witness.get("witness_id")),
        (trace.get("witness_digest"), artifact_digest(witness)),
        (projection.get("trace_ref"), trace.get("trace_id")),
        (projection.get("trace_digest"), artifact_digest(trace)),
        (projection.get("contract_ref"), f"contract:{contract.get('contract_id')}"),
    )
    if any(actual != expected for actual, expected in lineage):
        admissibility["provenance_valid"] = False
        return _not_evaluable(relation, "WITNESS_LINEAGE_MISMATCH", [], ["lineage"], admissibility)
    if relation.get("type") not in RELATION_TYPES:
        return _not_evaluable(relation, "UNSUPPORTED_RELATION_EVALUATOR", [], ["relation_type"], admissibility)
    missing = [ref for ref in refs if ref not in entries or entries[ref]["sufficiency"] != "SUFFICIENT"]
    if missing:
        reason = next((entries[ref]["reason_code"] for ref in missing if ref in entries), "MISSING_REQUIRED_OBSERVABLE")
        admissibility["evidence_complete"] = False
        admissibility["phase_reached"] = reason != "OBSERVATION_NOT_REACHED"
        admissibility["channel_valid"] = reason not in {"CHANNEL_UNAVAILABLE", "ACQUISITION_FAILED"}
        return _not_evaluable(relation, reason, missing, [], admissibility)
    invalid_correlation = [ref for ref in refs if entries[ref]["correlation_state"] in {"INCOMPLETE", "INVALID"}]
    if invalid_correlation:
        admissibility["correlation_valid"] = False
        return _not_evaluable(relation, "INCOMPLETE_CORRELATION", [], invalid_correlation, admissibility)
    if len(refs) > 1:
        subjects = {x["subject_ref"] for x in selected}; identities = {x["identity_group_ref"] for x in selected}; operations = {x["operation_ref"] for x in selected}
        if len(correlation_refs) != 1:
            admissibility["correlation_valid"] = False; return _not_evaluable(relation, "CORRELATION_INVALID", [], ["correlation_group"], admissibility)
        if len(subjects) != 1:
            admissibility["subject_valid"] = False; return _not_evaluable(relation, "SUBJECT_MISMATCH", [], ["subject"], admissibility)
        if len(identities) != 1:
            admissibility["identity_valid"] = False; return _not_evaluable(relation, "IDENTITY_MISMATCH", [], ["identity"], admissibility)
        if relation["type"] not in {"failure_propagation", "transition_constraint"} and len(operations) != 1:
            admissibility["correlation_valid"] = False; return _not_evaluable(relation, "OPERATION_MISMATCH", [], ["operation"], admissibility)
    observations: dict[str, Observation] = {}
    declarations = {x["observable_id"]: x for x in contract["observable_evidence"]["observables"]}
    for ref in refs:
        entry = entries[ref]; declaration = declarations[ref]
        value = None if entry["observation_status"] == "OBSERVED_ABSENCE" else entry["value"]
        observations[ref] = Observation(ref, True, value, declaration["value_type"], "execution_projection")
    operands = relation["operands"]
    if relation["type"] == "no_fatal_event":
        fatal_entry = entries[operands["fatal_event_ref"]]
        if fatal_entry["observation_status"] == "PRESENT" and fatal_entry["value_presence"] == "EXPLICIT_NULL":
            return _not_evaluable(relation, "INVALID_OBSERVABLE_DOMAIN", [], ["fatal_event"], admissibility)
    if relation["type"] == "full_consumption_on_success" and observations[operands["outcome_ref"]].value == "success":
        consumed = observations[operands["consumed_length_ref"]].value; total = observations[operands["input_length_ref"]].value
        if type(consumed) is int and type(total) is int and (consumed < 0 or total < 0 or consumed > total):
            return _not_evaluable(relation, "INVALID_OBSERVABLE_DOMAIN", [], ["consumption_domain"], admissibility)
    if relation["type"] == "state_invariant":
        length = observations[operands["length_ref"]].value
        if type(length) is int and length < 0:
            return _not_evaluable(relation, "INVALID_OBSERVABLE_DOMAIN", [], ["length_domain"], admissibility)
    if relation["type"] in {"transition_constraint", "failure_propagation"}:
        ordered_refs = (
            [operands["state_before_ref"], operands["state_after_ref"]]
            if relation["type"] == "transition_constraint"
            else [operands["inner_outcome_ref"], operands["outer_outcome_ref"]]
        )
        indices = [trace_by_id[entries[ref]["trace_evidence_refs"][0]]["sequence_index"] for ref in ordered_refs]
        if indices[0] >= indices[1]:
            admissibility["correlation_valid"] = False
            return _not_evaluable(relation, "ORDERING_INVALID", [], ["ordering"], admissibility)
    result = evaluate_relation_instance_observations(relation, observations)
    bindings = [{"contract_observable_ref": ref, "trace_evidence_refs": entries[ref]["trace_evidence_refs"]} for ref in refs]
    admissibility["broken_admissible"] = result.result == "BROKEN" and all(admissibility[k] for k in ("evidence_complete", "phase_reached", "channel_valid", "subject_valid", "identity_valid", "correlation_valid", "provenance_valid"))
    return _artifact(relation, result.result, result.reason_code, list(result.missing_observables), [], bindings, admissibility)


def evaluate_contract_relations(contract: Mapping[str, Any], witness: Mapping[str, Any], trace: Mapping[str, Any], projection: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [evaluate_relation_instance(relation, contract, witness, trace, projection) for relation in contract["expected_relation"]["relations"]]
