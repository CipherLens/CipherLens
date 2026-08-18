"""Campaign control routing. It consumes, but never changes, ExecutionVerdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from execution_trace.closure import build_unknown_closure
from pipeline_v2.model import ControlOutcome, RetryBudget


@dataclass
class BudgetState:
    total_attempts: int = 0
    candidate_attempts: dict[str, int] = field(default_factory=dict)
    same_binding_reruns: int = 0
    instrumentation_repairs: int = 0
    whole_binding_switches: int = 0
    completion_rounds: dict[str, int] = field(default_factory=dict)
    adaptations: dict[str, int] = field(default_factory=dict)


def reserve_attempt(state: BudgetState, budget: RetryBudget, candidate_ref: str) -> str | None:
    if state.total_attempts >= budget.max_total_attempts_per_contract_target:
        return ControlOutcome.ATTEMPT_BUDGET_EXHAUSTED.value
    if state.candidate_attempts.get(candidate_ref, 0) >= budget.max_execution_attempts_per_candidate:
        return ControlOutcome.ATTEMPT_BUDGET_EXHAUSTED.value
    state.total_attempts += 1
    state.candidate_attempts[candidate_ref] = state.candidate_attempts.get(candidate_ref, 0) + 1
    return None


def route_unknown_with_budget(*, verdict: Mapping[str, Any], state: BudgetState, budget: RetryBudget, reason_codes: list[str], missing_evidence: list[str], semantic_change_required: bool = False, merge_completion_available: bool = False, candidate_ref: str = "", merge_ref: str = "") -> tuple[Mapping[str, Any] | None, str]:
    closure = build_unknown_closure(verdict, reason_codes=reason_codes, missing_evidence=missing_evidence, semantic_change_required=semantic_change_required, merge_completion_available=merge_completion_available)
    if state.total_attempts >= budget.max_total_attempts_per_contract_target:
        return closure, ControlOutcome.ATTEMPT_BUDGET_EXHAUSTED.value
    if state.candidate_attempts.get(candidate_ref, 0) >= budget.max_execution_attempts_per_candidate:
        return closure, ControlOutcome.ATTEMPT_BUDGET_EXHAUSTED.value
    route = closure["plan"]["route"]
    exhausted = False
    if route == "SAME_BINDING_RERUN": exhausted = state.same_binding_reruns >= budget.max_same_binding_reruns
    elif route == "INSTRUMENTATION_REPAIR": exhausted = state.instrumentation_repairs >= budget.max_instrumentation_repairs
    elif route == "WHOLE_BINDING_SWITCH": exhausted = state.whole_binding_switches >= budget.max_whole_binding_switches
    elif route == "SAME_MERGE_COMPLETION": exhausted = state.completion_rounds.get(merge_ref, 0) >= budget.max_programmatic_completion_rounds
    if exhausted:
        return closure, ControlOutcome.EVIDENCE_EXHAUSTED.value
    if route == "SAME_BINDING_RERUN": state.same_binding_reruns += 1
    elif route == "INSTRUMENTATION_REPAIR": state.instrumentation_repairs += 1
    elif route == "WHOLE_BINDING_SWITCH": state.whole_binding_switches += 1
    elif route == "SAME_MERGE_COMPLETION": state.completion_rounds[merge_ref] = state.completion_rounds.get(merge_ref, 0) + 1
    return closure, route


def reserve_adaptation(state: BudgetState, budget: RetryBudget, merge_ref: str) -> str | None:
    if state.adaptations.get(merge_ref, 0) >= budget.max_constrained_adaptations_per_merge:
        return ControlOutcome.EVIDENCE_EXHAUSTED.value
    state.adaptations[merge_ref] = state.adaptations.get(merge_ref, 0) + 1
    return None
