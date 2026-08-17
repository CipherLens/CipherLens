"""Deterministic family-scoped derivation rules for Transfer Signatures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class FamilyEligibilityRule:
    rule_id: str
    excluded_semantics: tuple[tuple[str, Mapping[str, Any]], ...]
    correlation_scope: str


FAMILY_RULES: dict[str, FamilyEligibilityRule] = {
    "input_consumption": FamilyEligibilityRule(
        rule_id="ts.input_consumption.v0_1",
        excluded_semantics=(
            (
                "mandatory_complete_input_enforcement",
                {"operation_role": "PARSE"},
            ),
        ),
        correlation_scope="same_run",
    ),
    "failure_output_integrity": FamilyEligibilityRule(
        rule_id="ts.failure_output_integrity.v0_1",
        excluded_semantics=(
            (
                "failure_output_transactionality",
                {"operation_role": "FINAL", "output_role": "output_length"},
            ),
        ),
        correlation_scope="same_step",
    ),
    "object_state_consistency": FamilyEligibilityRule(
        rule_id="ts.object_state_consistency.v0_1",
        excluded_semantics=(
            (
                "atomic_clear_precludes_inconsistent_intermediate_state",
                {
                    "operation_role": "UPDATE",
                    "intervention_kind": "state_reuse_sequence",
                },
            ),
            (
                "mandatory_terminalization_precludes_followup",
                {
                    "operation_role": "UPDATE",
                    "intervention_kind": "state_reuse_sequence",
                },
            ),
        ),
        correlation_scope="same_subject",
    ),
}


def family_rule(contract_family: str) -> FamilyEligibilityRule:
    try:
        return FAMILY_RULES[contract_family]
    except KeyError as exc:
        raise ValueError(
            f"no Transfer Signature derivation rule for family {contract_family!r}"
        ) from exc
