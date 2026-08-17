"""Library-independent deterministic relation evaluation for VC v0.3."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence


RELATION_TYPES = frozenset({
    "outcome_requirement",
    "full_consumption_on_success",
    "output_preserved_on_failure",
    "state_invariant",
    "transition_constraint",
    "failure_propagation",
    "no_fatal_event",
})
RELATION_RESULTS = frozenset({"HOLDS", "BROKEN", "NOT_EVALUABLE"})
NORMALIZATION_RULES = frozenset({"identity", "mbedtls_zero_is_success", "parse_result_identity"})
INVARIANT_RULES = frozenset({"buffer_absent_implies_length_zero"})


@dataclass(frozen=True)
class Observation:
    observable_id: str
    present: bool
    value: Any
    value_type: str
    source: str

    def binding(self) -> dict[str, Any]:
        return {
            "observable_id": self.observable_id,
            "present": self.present,
            "value": self.value,
            "value_type": self.value_type,
            "source": self.source,
        }


@dataclass(frozen=True)
class RelationEvaluation:
    relation_id: str
    result: str
    evidence_bindings: tuple[dict[str, Any], ...]
    reason_code: str
    missing_observables: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation_id": self.relation_id,
            "result": self.result,
            "evidence_bindings": list(self.evidence_bindings),
            "reason_code": self.reason_code,
            "missing_observables": list(self.missing_observables),
        }


def evaluate_relation(
    relation: Mapping[str, Any], observations: Mapping[str, Observation]
) -> RelationEvaluation:
    """Evaluate one typed relation without parsing free text or legacy labels."""

    relation_id = str(relation.get("relation_id", ""))
    relation_type = relation.get("type")
    operands = relation.get("operands") or {}
    refs = _observable_refs(operands)
    if relation_type in {"full_consumption_on_success", "output_preserved_on_failure"}:
        outcome_ref = operands.get("outcome_ref")
        outcome_observation = observations.get(outcome_ref)
        if outcome_observation is None or not outcome_observation.present:
            return _result(
                relation_id,
                "NOT_EVALUABLE",
                observations,
                refs,
                "REQUIRED_OBSERVABLE_MISSING",
                (str(outcome_ref),),
            )
        outcome = outcome_observation.value
        inactive = (
            relation_type == "full_consumption_on_success" and outcome == "reject"
        ) or (relation_type == "output_preserved_on_failure" and outcome == "success")
        if inactive:
            return _result(relation_id, "HOLDS", observations, (outcome_ref,), "RELATION_NOT_ACTIVATED_NO_VIOLATION")
    missing = tuple(sorted(ref for ref in refs if ref not in observations or not observations[ref].present))
    if missing:
        return _result(relation_id, "NOT_EVALUABLE", observations, refs, "REQUIRED_OBSERVABLE_MISSING", missing)

    if relation_type == "outcome_requirement":
        outcome = observations[operands["outcome_ref"]].value
        if outcome not in {"success", "reject"}:
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        result = "HOLDS" if outcome == operands["expectation"] else "BROKEN"
        return _result(relation_id, result, observations, refs, "OUTCOME_MATCHED" if result == "HOLDS" else "OUTCOME_MISMATCH")

    if relation_type == "full_consumption_on_success":
        outcome = observations[operands["outcome_ref"]].value
        if outcome == "reject":
            return _result(relation_id, "HOLDS", observations, refs, "RELATION_NOT_ACTIVATED_NO_VIOLATION")
        if outcome != "success":
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        consumed = observations[operands["consumed_length_ref"]].value
        input_len = observations[operands["input_length_ref"]].value
        if not _integers(consumed, input_len):
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        result = "HOLDS" if consumed == input_len else "BROKEN"
        return _result(relation_id, result, observations, refs, "FULLY_CONSUMED" if result == "HOLDS" else "PARTIAL_CONSUMPTION")

    if relation_type == "output_preserved_on_failure":
        outcome = observations[operands["outcome_ref"]].value
        if outcome == "success":
            return _result(relation_id, "HOLDS", observations, refs, "RELATION_NOT_ACTIVATED_NO_VIOLATION")
        if outcome != "reject":
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        before = observations[operands["before_ref"]].value
        after = observations[operands["after_ref"]].value
        if type(before) is not type(after) or isinstance(before, (dict, list)):
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        result = "HOLDS" if before == after else "BROKEN"
        return _result(relation_id, result, observations, refs, "OUTPUT_PRESERVED" if result == "HOLDS" else "OUTPUT_CHANGED_ON_FAILURE")

    if relation_type == "state_invariant":
        if operands.get("invariant_id") != "buffer_absent_implies_length_zero":
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "UNKNOWN_INVARIANT")
        present = observations[operands["buffer_present_ref"]].value
        length = observations[operands["length_ref"]].value
        if type(present) is not bool or type(length) is not int:
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        holds = present or length == 0
        return _result(relation_id, "HOLDS" if holds else "BROKEN", observations, refs, "STATE_INVARIANT_HELD" if holds else "BUFFER_ABSENT_WITH_NONZERO_LENGTH")

    if relation_type == "transition_constraint":
        outcome = observations[operands["outcome_ref"]].value
        before = observations[operands["state_before_ref"]].value
        after = observations[operands["state_after_ref"]].value
        expected = operands["expected_state_ref"]
        if outcome not in {"success", "reject"} or not isinstance(before, str) or not isinstance(after, str):
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        if operands["policy"] == "required":
            holds = outcome == "success" and after == expected
        else:
            holds = outcome == "reject" or after != expected
        return _result(relation_id, "HOLDS" if holds else "BROKEN", observations, refs, "TRANSITION_CONSTRAINT_HELD" if holds else "TRANSITION_CONSTRAINT_BROKEN")

    if relation_type == "failure_propagation":
        inner = observations[operands["inner_outcome_ref"]].value
        outer = observations[operands["outer_outcome_ref"]].value
        if inner not in {"success", "reject"} or outer not in {"success", "reject"}:
            return _result(relation_id, "NOT_EVALUABLE", observations, refs, "WRONG_OBSERVABLE_TYPE")
        holds = inner != "reject" or outer == "reject"
        return _result(relation_id, "HOLDS" if holds else "BROKEN", observations, refs, "FAILURE_PROPAGATED" if holds else "FAILURE_SWALLOWED")

    if relation_type == "no_fatal_event":
        fatal = observations[operands["fatal_event_ref"]].value
        holds = fatal is None
        return _result(relation_id, "HOLDS" if holds else "BROKEN", observations, refs, "NO_FATAL_EVENT" if holds else "FATAL_EVENT_OBSERVED")

    return _result(relation_id, "NOT_EVALUABLE", observations, refs, "UNKNOWN_RELATION_TYPE")


def extract_observations(
    contract: Mapping[str, Any], events: Sequence[Any]
) -> tuple[dict[str, Observation], list[str]]:
    """Bind declared observables to one already validated source trace."""

    steps = contract["execution"]["steps"]
    step_events = {step["step_id"]: events[index] for index, step in enumerate(steps) if index < len(events)}
    extracted: dict[str, Observation] = {}
    errors: list[str] = []
    declarations = contract["observable_evidence"]["observables"]
    for declaration in declarations:
        observable_id = declaration["observable_id"]
        source = declaration["source"]
        event = events[-1] if source["phase"] == "process_end" and events else step_events.get(source.get("step_ref"))
        present, value = _extract_value(event, declaration["extraction"])
        observation = Observation(observable_id, present, value, declaration["value_type"], _source_label(source))
        extracted[observable_id] = observation
        if present and not _matches_declared_type(value, declaration["value_type"]):
            errors.append(f"{observable_id}: wrong observable type for {declaration['value_type']}")
    return extracted, sorted(errors)


def _extract_value(event: Any, extraction: Mapping[str, Any]) -> tuple[bool, Any]:
    if event is None:
        return False, None
    kind = extraction["kind"]
    field = extraction["field"]
    if kind == "out_state_field":
        out_state = getattr(event, "out_state", {})
        return (field in out_state, out_state.get(field))
    if kind in {"trace_field", "process_field"}:
        return (hasattr(event, field), getattr(event, field, None))
    if kind == "normalized_return":
        if not hasattr(event, field):
            return False, None
        return True, _normalize(extraction["rule_id"], getattr(event, field))
    return False, None


def _normalize(rule_id: str, value: Any) -> Any:
    if rule_id == "identity":
        return value
    if rule_id == "mbedtls_zero_is_success":
        return None if value is None else "success" if value == 0 else "reject"
    if rule_id == "parse_result_identity":
        return value if value in {"success", "reject"} else None
    raise ValueError(f"unknown normalization rule: {rule_id}")


def _observable_refs(operands: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(sorted(value for key, value in operands.items() if key.endswith("_ref") and key != "expected_state_ref" and isinstance(value, str)))


def _result(relation_id: str, result: str, observations: Mapping[str, Observation], refs: Sequence[str], reason: str, missing: Sequence[str] = ()) -> RelationEvaluation:
    bindings = tuple(observations[ref].binding() for ref in refs if ref in observations)
    return RelationEvaluation(relation_id, result, bindings, reason, tuple(missing))


def _integers(*values: Any) -> bool:
    return all(type(value) is int for value in values)


def _matches_declared_type(value: Any, value_type: str) -> bool:
    if value is None:
        return True
    if value_type in {"integer", "duration"}:
        return type(value) is int
    if value_type == "boolean":
        return type(value) is bool
    if value_type in {"enum", "outcome", "state", "event", "bytes"}:
        return isinstance(value, str)
    return False


def _source_label(source: Mapping[str, Any]) -> str:
    return f"{source['phase']}:{source.get('step_ref', 'process')}"
