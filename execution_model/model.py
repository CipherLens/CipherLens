"""Frozen vocabulary for the CipherLens v2 execution trust boundary."""

from __future__ import annotations

from enum import Enum


SCHEMA_VERSIONS = {
    "handoff": "cipherlens.execution_handoff.v0.1",
    "build_spec": "cipherlens.build_spec.v0.1",
    "build_record": "cipherlens.build_record.v0.1",
    "run_spec": "cipherlens.run_spec.v0.1",
    "run_record": "cipherlens.run_record.v0.1",
    "witness": "cipherlens.execution_witness.v0.1",
    "trace": "cipherlens.structured_execution_trace.v0.1",
    "projection": "cipherlens.contract_evidence_projection.v0.1",
    "relation_evaluation": "cipherlens.relation_instance_evaluation.v0.1",
    "verdict": "cipherlens.execution_verdict.v0.1",
    "closure": "cipherlens.execution_closure.v0.1",
    "violation_package": "cipherlens.violation_evidence_package.v0.1",
    "caller_bridge": "cipherlens.caller_impact_bridge.v0.1",
}

REGISTRY_VERSION = "cipherlens.execution_registry.v0.1"
RELATION_REGISTRY_VERSION = "cipherlens.guard_aware_relation_registry.v0.1"


class ExecutionAttemptOutcome(str, Enum):
    HANDOFF_REJECTED = "HANDOFF_REJECTED"
    BUILD_SPEC_REJECTED = "BUILD_SPEC_REJECTED"
    COMPILE_FAILED = "COMPILE_FAILED"
    LINK_FAILED = "LINK_FAILED"
    EXECUTABLE_MISSING = "EXECUTABLE_MISSING"
    RUN_SPEC_REJECTED = "RUN_SPEC_REJECTED"
    RUN_LAUNCH_FAILED = "RUN_LAUNCH_FAILED"
    LINEAGE_INTEGRITY_FAILED = "LINEAGE_INTEGRITY_FAILED"
    EXECUTOR_FAILURE = "EXECUTOR_FAILURE"
    WITNESS_FORMED = "WITNESS_FORMED"


class BuildPhase(str, Enum):
    COMPILE = "COMPILE"
    LINK = "LINK"


class PhaseResult(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"
    LAUNCH_FAILED = "LAUNCH_FAILED"
    TIMED_OUT = "TIMED_OUT"


class BuildResult(str, Enum):
    BUILT = "BUILT"
    COMPILE_FAILED = "COMPILE_FAILED"
    LINK_FAILED = "LINK_FAILED"
    TOOLCHAIN_LAUNCH_FAILED = "TOOLCHAIN_LAUNCH_FAILED"
    BUILD_TIMED_OUT = "BUILD_TIMED_OUT"
    OUTPUT_MISSING = "OUTPUT_MISSING"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"


class ProcessStart(str, Enum):
    STARTED = "STARTED"
    LAUNCH_FAILED = "LAUNCH_FAILED"


class Termination(str, Enum):
    EXITED = "EXITED"
    SIGNALED = "SIGNALED"
    TIMED_OUT = "TIMED_OUT"
    COLLECTION_ABORTED = "COLLECTION_ABORTED"
    NOT_STARTED = "NOT_STARTED"


class CollectionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class WitnessStatus(str, Enum):
    VALID_WITNESS = "VALID_WITNESS"
    PARTIAL_WITNESS = "PARTIAL_WITNESS"
    INVALID_WITNESS = "INVALID_WITNESS"


class ObservationStatus(str, Enum):
    PRESENT = "PRESENT"
    OBSERVED_ABSENCE = "OBSERVED_ABSENCE"
    NOT_REACHED = "NOT_REACHED"
    CHANNEL_UNAVAILABLE = "CHANNEL_UNAVAILABLE"
    ACQUISITION_FAILED = "ACQUISITION_FAILED"
    INVALID_VALUE = "INVALID_VALUE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"


class ValuePresence(str, Enum):
    VALUE = "VALUE"
    ARTIFACT = "ARTIFACT"
    EXPLICIT_NULL = "EXPLICIT_NULL"
    NONE = "NONE"


class Sufficiency(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    CONFLICTING = "CONFLICTING"


class CorrelationState(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


class RelationResult(str, Enum):
    HOLDS = "HOLDS"
    BROKEN = "BROKEN"
    NOT_EVALUABLE = "NOT_EVALUABLE"


class ExecutionVerdict(str, Enum):
    SATISFIED = "SATISFIED"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"


class ClosureRoute(str, Enum):
    SAME_BINDING_RERUN = "SAME_BINDING_RERUN"
    SAME_MERGE_COMPLETION = "SAME_MERGE_COMPLETION"
    INSTRUMENTATION_REPAIR = "INSTRUMENTATION_REPAIR"
    WHOLE_BINDING_SWITCH = "WHOLE_BINDING_SWITCH"


SEMANTIC_EVIDENCE_TYPES = frozenset({
    "return_value", "error_code", "operation_outcome", "output_bytes",
    "output_length", "consumed_length", "input_length", "object_state",
    "state_transition", "subsequent_behavior", "fatal_event", "timing",
})
PROCESS_EVIDENCE_TYPES = frozenset({
    "process_exit", "signal", "sanitizer_event", "stdout_marker",
    "stderr_marker", "timeout", "runtime_error",
})
BUILD_EVIDENCE_TYPES = frozenset({
    "compile_diagnostic", "link_diagnostic", "build_output",
})

UNKNOWN_REASONS = frozenset({
    "MISSING_REQUIRED_OBSERVABLE", "INCOMPLETE_CORRELATION",
    "OBSERVATION_NOT_REACHED", "CHANNEL_UNAVAILABLE", "ACQUISITION_FAILED",
    "PARTIAL_WITNESS", "RELATION_PRECONDITION_NOT_MET",
    "RELATION_NOT_EVALUABLE", "TRACE_EVIDENCE_CONFLICT",
    "UNSUPPORTED_RELATION_EVALUATOR", "INSTRUMENTATION_FAILURE",
})


class ExecutionModelError(ValueError):
    """Raised when a canonical artifact violates its closed contract."""

    def __init__(self, kind: str, errors: list[str] | tuple[str, ...]):
        self.kind = kind
        self.errors = tuple(sorted(dict.fromkeys(errors)))
        super().__init__(f"invalid {kind}:\n" + "\n".join(f"- {x}" for x in self.errors))
