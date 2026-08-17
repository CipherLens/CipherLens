"""Closed Transfer Signature constraint and target-fact registries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from contract_miner.roles import (
    INTERVENTION_KINDS,
    OBJECT_ROLES,
    OBSERVABLE_ROLES,
    OPERATION_ROLES,
    PRECONDITION_PREDICATES,
    VALUE_TYPES,
)
from transfer_signature.model import ConstraintClass


@dataclass(frozen=True)
class ConstraintSpec:
    constraint_class: ConstraintClass
    fact_type: str
    required_parameters: frozenset[str]


CONSTRAINT_REGISTRY: dict[str, ConstraintSpec] = {
    "supports_operation_role": ConstraintSpec(
        ConstraintClass.REQUIRED_CAPABILITY,
        "operation_role",
        frozenset({"role", "subject_role"}),
    ),
    "supports_object_role": ConstraintSpec(
        ConstraintClass.REQUIRED_CAPABILITY,
        "object_role",
        frozenset({"role", "value_type"}),
    ),
    "supports_precondition_shape": ConstraintSpec(
        ConstraintClass.REQUIRED_CAPABILITY,
        "precondition_shape",
        frozenset({"predicate_id", "operand_roles"}),
    ),
    "permits_equivalent_intervention": ConstraintSpec(
        ConstraintClass.REQUIRED_CAPABILITY,
        "equivalent_intervention",
        frozenset({"kind", "target_role"}),
    ),
    "supports_execution_shape": ConstraintSpec(
        ConstraintClass.REQUIRED_CAPABILITY,
        "execution_shape",
        frozenset({"roles", "subject_roles", "continuity"}),
    ),
    "mandatory_complete_input_enforcement": ConstraintSpec(
        ConstraintClass.EXCLUDED_SEMANTIC,
        "complete_input_enforcement",
        frozenset({"operation_role"}),
    ),
    "failure_output_transactionality": ConstraintSpec(
        ConstraintClass.EXCLUDED_SEMANTIC,
        "failure_output_transactionality",
        frozenset({"operation_role", "output_role"}),
    ),
    "atomic_clear_precludes_inconsistent_intermediate_state": ConstraintSpec(
        ConstraintClass.EXCLUDED_SEMANTIC,
        "atomic_clear_semantics",
        frozenset({"operation_role", "intervention_kind"}),
    ),
    "mandatory_terminalization_precludes_followup": ConstraintSpec(
        ConstraintClass.EXCLUDED_SEMANTIC,
        "terminalization_after_operation",
        frozenset({"operation_role", "intervention_kind"}),
    ),
    "contract_observable_resolvable": ConstraintSpec(
        ConstraintClass.REQUIRED_OBSERVABILITY,
        "observable_channel",
        frozenset({"observable_ref"}),
    ),
    "observable_set_correlatable": ConstraintSpec(
        ConstraintClass.REQUIRED_OBSERVABILITY,
        "observable_correlation",
        frozenset({"observable_refs", "correlation_scope"}),
    ),
}


FACT_PARAMETER_KEYS: dict[str, frozenset[str]] = {
    "operation_role": frozenset({"role", "subject_role"}),
    "object_role": frozenset({"role", "value_type"}),
    "precondition_shape": frozenset({"predicate_id", "operand_roles"}),
    "equivalent_intervention": frozenset({"kind", "target_role"}),
    "execution_shape": frozenset(
        {"roles", "subject_roles", "continuity", "participant_refs"}
    ),
    "complete_input_enforcement": frozenset({"operation_role"}),
    "failure_output_transactionality": frozenset(
        {"operation_role", "output_role"}
    ),
    "atomic_clear_semantics": frozenset(
        {"operation_role", "intervention_kind"}
    ),
    "terminalization_after_operation": frozenset(
        {"operation_role", "intervention_kind"}
    ),
    "observable_channel": frozenset(
        {
            "observable_ref",
            "semantic_role",
            "value_type",
            "phase",
            "operation_role",
        }
    ),
    "observable_correlation": frozenset(
        {"observable_refs", "correlation_scope", "participant_refs"}
    ),
}


LIST_PARAMETERS = frozenset(
    {"operand_roles", "roles", "subject_roles", "participant_refs", "observable_refs"}
)

CONTINUITIES = frozenset({"single_subject", "multi_subject"})
CORRELATION_SCOPES = frozenset({"same_run", "same_step", "same_subject"})
OBSERVABLE_PHASES = frozenset(
    {"before_step", "after_step", "between_steps", "process_end"}
)
OUTPUT_ROLES = frozenset({"output_length"})


def constraint_spec(constraint_type: str) -> ConstraintSpec:
    try:
        return CONSTRAINT_REGISTRY[constraint_type]
    except KeyError as exc:
        raise ValueError(f"unknown constraint type {constraint_type!r}") from exc


def validate_constraint_parameters(
    constraint_type: str, parameters: Any, path: str
) -> list[str]:
    errors: list[str] = []
    spec = CONSTRAINT_REGISTRY.get(constraint_type)
    if spec is None:
        return [f"{path.rsplit('.', 1)[0]}.type: unknown constraint type {constraint_type!r}"]
    if not isinstance(parameters, dict):
        return [f"{path}: expected object"]
    _exact_keys(parameters, spec.required_parameters, path, errors)
    _validate_parameter_values(constraint_type, parameters, path, errors)
    return errors


def validate_fact_parameters(fact_type: str, parameters: Any, path: str) -> list[str]:
    errors: list[str] = []
    expected = FACT_PARAMETER_KEYS.get(fact_type)
    if expected is None:
        return [f"{path.rsplit('.', 1)[0]}.fact_type: unknown fact type {fact_type!r}"]
    if not isinstance(parameters, dict):
        return [f"{path}: expected object"]
    _exact_keys(parameters, expected, path, errors)
    _validate_parameter_values(fact_type, parameters, path, errors)
    return errors


def _exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], path: str, errors: list[str]
) -> None:
    for key in sorted(expected - set(value)):
        errors.append(f"{path}.{key}: required field missing")
    for key in sorted(set(value) - expected):
        errors.append(f"{path}.{key}: unknown field")


def _validate_parameter_values(
    semantic_type: str,
    parameters: Mapping[str, Any],
    path: str,
    errors: list[str],
) -> None:
    for key, value in parameters.items():
        item_path = f"{path}.{key}"
        if key in LIST_PARAMETERS:
            if not isinstance(value, list) or not value:
                errors.append(f"{item_path}: expected non-empty list[string]")
            elif not all(isinstance(item, str) and item for item in value):
                errors.append(f"{item_path}: expected non-empty list[string]")
        elif not isinstance(value, str) or not value:
            errors.append(f"{item_path}: expected non-empty string")
    if "continuity" in parameters and parameters.get("continuity") not in CONTINUITIES:
        errors.append(f"{path}.continuity: unknown value {parameters.get('continuity')!r}")
    if (
        "correlation_scope" in parameters
        and parameters.get("correlation_scope") not in CORRELATION_SCOPES
    ):
        errors.append(
            f"{path}.correlation_scope: unknown value {parameters.get('correlation_scope')!r}"
        )
    observable_operations = OPERATION_ROLES | frozenset({"PROCESS_END"})
    enum_checks: tuple[tuple[str, frozenset[str]], ...] = (
        (
            "operation_role",
            observable_operations if semantic_type == "observable_channel" else OPERATION_ROLES,
        ),
        ("subject_role", OBJECT_ROLES),
        ("target_role", OBJECT_ROLES),
        ("predicate_id", PRECONDITION_PREDICATES),
        ("kind", INTERVENTION_KINDS),
        ("intervention_kind", INTERVENTION_KINDS),
        ("value_type", VALUE_TYPES),
        ("semantic_role", OBSERVABLE_ROLES),
        ("phase", OBSERVABLE_PHASES),
        ("output_role", OUTPUT_ROLES),
    )
    for key, allowed in enum_checks:
        if key in parameters and parameters.get(key) not in allowed:
            errors.append(f"{path}.{key}: unknown value {parameters.get(key)!r}")
    if "role" in parameters:
        allowed = OBJECT_ROLES if semantic_type in {"supports_object_role", "object_role"} else OPERATION_ROLES
        if parameters.get("role") not in allowed:
            errors.append(f"{path}.role: unknown value {parameters.get('role')!r}")
    for key in ("roles",):
        if key in parameters and isinstance(parameters.get(key), list):
            for index, value in enumerate(parameters[key]):
                if value not in OPERATION_ROLES:
                    errors.append(f"{path}.{key}[{index}]: unknown value {value!r}")
    for key in ("subject_roles", "operand_roles"):
        if key in parameters and isinstance(parameters.get(key), list):
            for index, value in enumerate(parameters[key]):
                if value not in OBJECT_ROLES:
                    errors.append(f"{path}.{key}[{index}]: unknown value {value!r}")
