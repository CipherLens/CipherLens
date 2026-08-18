"""Campaign bookkeeping separated from the sole canonical ExecutionVerdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from pipeline_v2.model import CampaignAttemptOutcome, ControlOutcome, RetryBudget
from pipeline_v2.routing import BudgetState, reserve_attempt, route_unknown_with_budget


@dataclass(frozen=True)
class CampaignPolicy:
    retry_budget: RetryBudget = RetryBudget()
    stop_on_first_violated: bool = False


@dataclass
class CampaignState:
    campaign_id: str
    policy: CampaignPolicy = CampaignPolicy()
    budget_state: BudgetState = field(default_factory=BudgetState)
    attempts: list[Mapping[str, Any]] = field(default_factory=list)
    impact_job_states: list[str] = field(default_factory=list)
    terminal_control_outcome: str | None = None
    _retry_sequence: int = 0

    def begin_attempt(self, candidate_ref: str) -> str | None:
        return reserve_attempt(self.budget_state, self.policy.retry_budget, candidate_ref)

    def record_attempt(self, result: Mapping[str, Any]) -> None:
        self.attempts.append(dict(result))
        if result.get("outcome") == CampaignAttemptOutcome.VIOLATED_WITNESS.value and self.policy.stop_on_first_violated:
            self.terminal_control_outcome = ControlOutcome.POLICY_STOPPED.value

    def schedule_unknown(self, *, attempt_id: str, verdict: Mapping[str, Any], candidate_ref: str, merge_ref: str, binding_ref: str, surface_refs: Sequence[str] = (), reason_codes: list[str], missing_evidence: list[str], semantic_change_required: bool = False, merge_completion_available: bool = False) -> "RetryInstruction":
        """Return a new immutable attempt instruction; do not overwrite UNKNOWN."""
        closure, route = route_unknown_with_budget(
            verdict=verdict, state=self.budget_state, budget=self.policy.retry_budget,
            reason_codes=reason_codes, missing_evidence=missing_evidence,
            semantic_change_required=semantic_change_required,
            merge_completion_available=merge_completion_available,
            candidate_ref=candidate_ref, merge_ref=merge_ref,
        )
        if route in {ControlOutcome.EVIDENCE_EXHAUSTED.value, ControlOutcome.ATTEMPT_BUDGET_EXHAUSTED.value}:
            self.terminal_control_outcome = route
            return RetryInstruction(None, route, closure, (), ())
        self._retry_sequence += 1
        exclusions = (binding_ref,) if route == "WHOLE_BINDING_SWITCH" else ()
        surface_exclusions = tuple(sorted(set(surface_refs))) if route == "WHOLE_BINDING_SWITCH" else ()
        return RetryInstruction(f"{attempt_id}:retry:{self._retry_sequence}", route, closure, exclusions, surface_exclusions)


@dataclass(frozen=True)
class RetryInstruction:
    attempt_id: str | None
    route: str
    closure: Mapping[str, Any] | None
    excluded_binding_refs: tuple[str, ...]
    excluded_surface_refs: tuple[str, ...]


def dispatch_retry(instruction: RetryInstruction, executors: Mapping[str, Callable[[RetryInstruction], Any]]) -> Any:
    """Invoke an explicitly injected route executor; never silently downgrade."""
    if instruction.attempt_id is None:
        raise ValueError("budget-exhausted instruction is not executable")
    executor = executors.get(instruction.route)
    if executor is None:
        raise ValueError(f"retry executor is not configured: {instruction.route}")
    result = executor(instruction)
    if getattr(result, "attempt_id", None) != instruction.attempt_id:
        raise ValueError("retry executor returned the wrong attempt lineage")
    return result


@dataclass(frozen=True)
class CampaignSummary:
    campaign_id: str
    attempt_refs: tuple[str, ...]
    attempt_outcomes: Mapping[str, int]
    execution_verdict_counts: Mapping[str, int]
    violation_package_refs: tuple[str, ...]
    impact_job_states: tuple[str, ...]
    terminal_control_outcome: str | None
    stop_reason: str | None

    @classmethod
    def from_state(cls, state: CampaignState) -> "CampaignSummary":
        outcomes: dict[str, int] = {}; verdicts: dict[str, int] = {}; packages: list[str] = []; refs: list[str] = []
        for item in state.attempts:
            refs.append(str(item.get("attempt_id", "")))
            outcome = str(item.get("outcome", "")); outcomes[outcome] = outcomes.get(outcome, 0) + 1
            verdict = item.get("execution_verdict")
            if verdict: verdicts[str(verdict)] = verdicts.get(str(verdict), 0) + 1
            package = item.get("violation_package_ref")
            if package: packages.append(str(package))
        return cls(state.campaign_id, tuple(refs), outcomes, verdicts, tuple(packages), tuple(state.impact_job_states), state.terminal_control_outcome, state.terminal_control_outcome)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "cipherlens.campaign_summary.v0.1", "campaign_id": self.campaign_id, "attempt_refs": list(self.attempt_refs), "attempt_outcomes": dict(self.attempt_outcomes), "execution_verdict_counts": dict(self.execution_verdict_counts), "violation_package_refs": list(self.violation_package_refs), "impact_job_states": list(self.impact_job_states), "terminal_control_outcome": self.terminal_control_outcome, "stop_reason": self.stop_reason}
