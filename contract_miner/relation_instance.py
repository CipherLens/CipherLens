"""Shared guard-aware relation API for canonical source and target adapters."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from contract_miner.relations import Observation, RelationEvaluation, evaluate_relation, extract_observations


def evaluate_relation_instance_observations(
    relation: Mapping[str, Any], observations: Mapping[str, Observation]
) -> RelationEvaluation:
    """Apply canonical conditional guards, then reuse the v0.3 comparator."""

    relation_type = relation.get("type")
    operands = relation.get("operands") or {}
    if relation_type in {"full_consumption_on_success", "output_preserved_on_failure"}:
        outcome_ref = str(operands.get("outcome_ref") or "")
        outcome = observations.get(outcome_ref)
        if outcome is None or not outcome.present:
            return RelationEvaluation(
                str(relation.get("relation_id") or ""), "NOT_EVALUABLE", (),
                "REQUIRED_OBSERVABLE_MISSING", (outcome_ref,),
            )
        inactive = (
            relation_type == "full_consumption_on_success" and outcome.value == "reject"
        ) or (
            relation_type == "output_preserved_on_failure" and outcome.value == "success"
        )
        if inactive:
            return RelationEvaluation(
                str(relation.get("relation_id") or ""), "NOT_EVALUABLE",
                (outcome.binding(),), "PRECONDITION_NOT_MET", (),
            )
    return evaluate_relation(relation, observations)


def evaluate_source_trace_relations(
    contract: Mapping[str, Any], events: Sequence[Any]
) -> tuple[list[RelationEvaluation], list[str]]:
    """Canonical source-side adapter sharing the same relation-instance API."""

    observations, errors = extract_observations(contract, events)
    results = [
        evaluate_relation_instance_observations(relation, observations)
        for relation in contract["expected_relation"]["relations"]
    ]
    return results, errors
