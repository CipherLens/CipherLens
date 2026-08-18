"""Operational vocabulary for v2 orchestration; it has no security authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AttemptEventType(str, Enum):
    CREATED = "CREATED"; MATCHING = "MATCHING"; MATCHED = "MATCHED"
    MERGING = "MERGING"; COMPLETING = "COMPLETING"; ADAPTING = "ADAPTING"
    HANDOFF_ACCEPTED = "HANDOFF_ACCEPTED"; BUILDING = "BUILDING"; BUILT = "BUILT"
    RUNNING = "RUNNING"; RAN = "RAN"; WITNESS_FORMED = "WITNESS_FORMED"
    TRACE_NORMALIZED = "TRACE_NORMALIZED"; PROJECTED = "PROJECTED"
    EVALUATED = "EVALUATED"; VERDICTED = "VERDICTED"; ROUTED = "ROUTED"; CLOSED = "CLOSED"


class CampaignAttemptOutcome(str, Enum):
    MATCHER_NO_MATCH = "MATCHER_NO_MATCH"; MATCHER_FAILURE = "MATCHER_FAILURE"
    MERGE_FAILURE = "MERGE_FAILURE"; ADAPTATION_FAILURE = "ADAPTATION_FAILURE"
    HANDOFF_FAILURE = "HANDOFF_FAILURE"; BUILD_FAILURE = "BUILD_FAILURE"
    RUN_LAUNCH_FAILURE = "RUN_LAUNCH_FAILURE"; WITNESS_INVALID = "WITNESS_INVALID"
    SATISFIED_WITNESS = "SATISFIED_WITNESS"; EXECUTION_UNKNOWN = "EXECUTION_UNKNOWN"
    VIOLATED_WITNESS = "VIOLATED_WITNESS"


class ControlOutcome(str, Enum):
    SEARCH_SPACE_EXHAUSTED = "SEARCH_SPACE_EXHAUSTED"
    EVIDENCE_EXHAUSTED = "EVIDENCE_EXHAUSTED"
    ATTEMPT_BUDGET_EXHAUSTED = "ATTEMPT_BUDGET_EXHAUSTED"
    POLICY_STOPPED = "POLICY_STOPPED"; CAMPAIGN_FAILURE = "CAMPAIGN_FAILURE"


class FailureKind(str, Enum):
    MATCHER_FAILURE = "MATCHER_FAILURE"; MATCHER_NO_MATCH = "MATCHER_NO_MATCH"
    MERGE_FAILURE = "MERGE_FAILURE"; ADAPTATION_FAILURE = "ADAPTATION_FAILURE"
    HANDOFF_FAILURE = "HANDOFF_FAILURE"; ARTIFACT_INTEGRITY_FAILURE = "ARTIFACT_INTEGRITY_FAILURE"
    BUILD_FAILURE = "BUILD_FAILURE"; RUN_LAUNCH_FAILURE = "RUN_LAUNCH_FAILURE"
    WITNESS_INVALID = "WITNESS_INVALID"; EXECUTION_UNKNOWN = "EXECUTION_UNKNOWN"
    IMPACT_ANALYSIS_FAILURE = "IMPACT_ANALYSIS_FAILURE"; REPLAY_FAILURE = "REPLAY_FAILURE"


@dataclass(frozen=True)
class RetryBudget:
    max_same_binding_reruns: int = 2
    max_instrumentation_repairs: int = 1
    max_whole_binding_switches: int = 3
    max_execution_attempts_per_candidate: int = 4
    max_total_attempts_per_contract_target: int = 12
    max_programmatic_completion_rounds: int = 1
    max_constrained_adaptations_per_merge: int = 1

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.__dict__.values()):
            raise ValueError("retry budgets must be non-negative")
