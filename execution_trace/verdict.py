"""Deterministic all_of aggregation into the only execution-level Verdict."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from execution_model.canonical import artifact_digest, identify
from execution_model.model import ExecutionVerdict, REGISTRY_VERSION, SCHEMA_VERSIONS
from execution_model.registry import validate_artifact_or_raise


def aggregate_execution_verdict(
    contract: Mapping[str, Any], candidate_binding: Mapping[str, Any], merge: Mapping[str, Any],
    witness: Mapping[str, Any] | None, trace: Mapping[str, Any] | None,
    evaluations: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    if witness is None or trace is None or witness.get("status") == "INVALID_WITNESS": return None
    expected_relations = {x["relation_id"] for x in contract["expected_relation"]["relations"]}
    actual_relations = [x.get("relation_instance_ref") for x in evaluations]
    lineage_valid = (
        witness.get("contract_ref") == f"contract:{contract.get('contract_id')}"
        and witness.get("candidate_binding_ref") == candidate_binding.get("binding_id")
        and witness.get("merge_ref") == merge.get("merge_id")
        and trace.get("witness_ref") == witness.get("witness_id")
        and trace.get("witness_digest") == artifact_digest(witness)
        and set(actual_relations) == expected_relations
        and len(actual_relations) == len(expected_relations)
        and all(x.get("witness_ref") == witness.get("witness_id") and x.get("trace_ref") == trace.get("trace_id") for x in evaluations)
    )
    if not lineage_valid:
        return None
    broken = [x for x in evaluations if x.get("result") == "BROKEN" and (x.get("admissibility") or {}).get("broken_admissible") is True]
    non_eval = [x for x in evaluations if x.get("result") == "NOT_EVALUABLE"]
    all_holds = bool(evaluations) and all(x.get("result") == "HOLDS" for x in evaluations)
    if broken:
        verdict, reasons = ExecutionVerdict.VIOLATED.value, ["ADMISSIBLE_BROKEN_RELATION"]
    elif witness.get("status") == "VALID_WITNESS" and all_holds:
        verdict, reasons = ExecutionVerdict.SATISFIED.value, ["ALL_REQUIRED_RELATIONS_HOLD"]
    else:
        verdict, reasons = ExecutionVerdict.UNKNOWN.value, ["REQUIRED_RELATION_NOT_EVALUABLE"]
        if witness.get("status") == "PARTIAL_WITNESS": reasons.append("PARTIAL_WITNESS")
    document = identify({
        "schema_version": SCHEMA_VERSIONS["verdict"], "verdict_id": "pending",
        "contract_ref": witness["contract_ref"], "contract_digest": witness["contract_digest"],
        "candidate_binding_ref": candidate_binding["binding_id"], "candidate_binding_digest": witness["candidate_binding_digest"],
        "merge_ref": merge["merge_id"], "merge_digest": witness["merge_digest"],
        "witness_ref": witness["witness_id"], "witness_digest": artifact_digest(witness),
        "trace_ref": trace["trace_id"], "trace_digest": artifact_digest(trace),
        "relation_evaluations": [{"ref": x["evaluation_id"], "digest": artifact_digest(x)} for x in evaluations],
        "verdict": verdict, "supporting_broken_relation_refs": [x["evaluation_id"] for x in broken],
        "non_evaluable_relation_refs": [x["evaluation_id"] for x in non_eval], "reason_codes": reasons,
        "evidence_sufficiency_summary": {"total": len(evaluations), "holds": sum(x["result"] == "HOLDS" for x in evaluations), "broken": len(broken), "not_evaluable": len(non_eval), "witness_status": witness["status"]},
        "producer": "execution_trace.verdict", "registry_version": REGISTRY_VERSION,
    })
    validate_artifact_or_raise(document); return document
