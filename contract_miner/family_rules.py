"""Deterministic family extraction rules that emit library-independent P/O."""

from __future__ import annotations

from typing import Any, Callable, Mapping


RULE_IDS = frozenset({
    "parser_full_consumption_v1",
    "failure_output_preservation_v1",
    "pointer_length_state_consistency_v1",
})


def apply_family_rule(rule_id: str, parameters: Mapping[str, Any], evidence_refs: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return Expected Relation P and Observable Evidence O for one family."""
    try:
        builder = _RULES[rule_id]
    except KeyError as exc:
        raise ValueError(f"unsupported family rule: {rule_id}") from exc
    return builder(parameters, evidence_refs)


def _observable(observable_id: str, semantic_role: str, value_type: str, requirement: str, step_ref: str, kind: str, field: str, evidence_refs: list[str], rule_id: str | None = None) -> dict[str, Any]:
    extraction = {"kind": kind, "field": field}
    if rule_id is not None:
        extraction["rule_id"] = rule_id
    return {
        "observable_id": observable_id,
        "semantic_role": semantic_role,
        "source": {"phase": "after_step", "step_ref": step_ref},
        "value_type": value_type,
        "requirement": requirement,
        "extraction": extraction,
        "provenance_refs": evidence_refs,
    }


def _parser(parameters: Mapping[str, Any], evidence_refs: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    step = _required(parameters, "parse_step_ref")
    outcome = _observable("PARSE_OUTCOME", "operation_outcome", "outcome", "required", step, "normalized_return", "ret", evidence_refs, "mbedtls_zero_is_success")
    consumed = _observable("CONSUMED_LENGTH", "consumed_length", "integer", "conditional", step, "trace_field", "consumed_len", evidence_refs)
    input_len = _observable("INPUT_LENGTH", "input_length", "integer", "conditional", step, "trace_field", "input_len", evidence_refs)
    p = {
        "aggregation": "all_of",
        "summary": "A successful whole-object parse must consume the complete declared input.",
        "relations": [{
            "relation_id": "FULL_CONSUMPTION",
            "type": "full_consumption_on_success",
            "criticality": "primary",
            "operands": {"outcome_ref": "PARSE_OUTCOME", "consumed_length_ref": "CONSUMED_LENGTH", "input_length_ref": "INPUT_LENGTH"},
        }],
    }
    return p, {"observables": [outcome, consumed, input_len]}


def _output_preservation(parameters: Mapping[str, Any], evidence_refs: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    step = _required(parameters, "final_step_ref")
    observables = [
        _observable("FINAL_OUTCOME", "operation_outcome", "outcome", "required", step, "normalized_return", "ret", evidence_refs, "mbedtls_zero_is_success"),
        _observable("OUTPUT_LENGTH_BEFORE", "output_length", "integer", "conditional", step, "out_state_field", "output_length_before", evidence_refs),
        _observable("OUTPUT_LENGTH_AFTER", "output_length", "integer", "conditional", step, "out_state_field", "output_length_after", evidence_refs),
    ]
    p = {
        "aggregation": "all_of",
        "summary": "Invalid padding must be rejected without changing caller-visible output length.",
        "relations": [
            {"relation_id": "INVALID_INPUT_REJECTED", "type": "outcome_requirement", "criticality": "primary", "operands": {"outcome_ref": "FINAL_OUTCOME", "expectation": "reject"}},
            {"relation_id": "OUTPUT_PRESERVED", "type": "output_preserved_on_failure", "criticality": "primary", "operands": {"outcome_ref": "FINAL_OUTCOME", "before_ref": "OUTPUT_LENGTH_BEFORE", "after_ref": "OUTPUT_LENGTH_AFTER"}},
        ],
    }
    return p, {"observables": observables}


def _pointer_state(parameters: Mapping[str, Any], evidence_refs: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    zero_step = _required(parameters, "zero_update_step_ref")
    reuse_step = _required(parameters, "reuse_step_ref")
    observables = [
        _observable("BUFFER_PRESENT_AFTER_ZERO", "object_state", "boolean", "required", zero_step, "out_state_field", "buffer_present", evidence_refs),
        _observable("STORED_LENGTH_AFTER_ZERO", "object_state", "integer", "required", zero_step, "out_state_field", "stored_length", evidence_refs),
        _observable("REUSE_FATAL_EVENT", "fatal_event", "event", "required", reuse_step, "trace_field", "sanitizer_event", evidence_refs),
    ]
    p = {
        "aggregation": "all_of",
        "summary": "Clearing a value must preserve pointer-length consistency and subsequent reuse must not cause a fatal event.",
        "relations": [
            {"relation_id": "POINTER_LENGTH_CONSISTENT", "type": "state_invariant", "criticality": "primary", "operands": {"invariant_id": "buffer_absent_implies_length_zero", "buffer_present_ref": "BUFFER_PRESENT_AFTER_ZERO", "length_ref": "STORED_LENGTH_AFTER_ZERO"}},
            {"relation_id": "REUSE_NO_FATAL_EVENT", "type": "no_fatal_event", "criticality": "primary", "operands": {"fatal_event_ref": "REUSE_FATAL_EVENT"}},
        ],
    }
    return p, {"observables": observables}


def _required(parameters: Mapping[str, Any], key: str) -> str:
    value = parameters.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"family rule parameter {key!r} is required")
    return value


_RULES: dict[str, Callable[[Mapping[str, Any], list[str]], tuple[dict[str, Any], dict[str, Any]]]] = {
    "parser_full_consumption_v1": _parser,
    "failure_output_preservation_v1": _output_preservation,
    "pointer_length_state_consistency_v1": _pointer_state,
}
