"""Load and validate CipherLens Vulnerability Contract v0.2 documents."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any, Mapping

import yaml


_SCHEMA_PATH = Path(__file__).with_name("vc.schema.yaml")
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent


class VCLoadError(ValueError):
    """Raised when a Vulnerability Contract YAML file cannot be loaded safely."""


class VCValidationError(ValueError):
    """Raised when a Vulnerability Contract has one or more validation errors."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        message = "invalid vulnerability contract:\n" + "\n".join(
            f"- {error}" for error in self.errors
        )
        super().__init__(message)


def load_vc(path: str | Path) -> Any:
    """Load a VC YAML document with PyYAML's safe loader."""

    source = Path(path)
    try:
        return yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise VCLoadError(f"cannot load VC YAML '{source}': {exc}") from exc


def validate_vc(vc: Any, repo_root: str | Path | None = None) -> list[str]:
    """Return every structural and semantic M0 validation error in stable order."""

    schema = _load_schema_definition()
    errors: list[str] = []
    if not _validate_object(vc, "$", "contract", schema, errors):
        return _stable_errors(errors)

    _validate_field(vc.get("contract_id"), "contract_id", "contract_id", schema, errors)
    _validate_field(
        vc.get("schema_version"), "schema_version", "schema_version", schema, errors
    )

    source = _child_object(vc, "source", "source", schema, errors)
    if source is not None:
        for key in ("pattern_id", "library", "buggy_version", "fixed_version"):
            if key in source:
                _validate_field(
                    source[key], f"source.{key}", f"source.{key}", schema, errors
                )
        _validate_list_field(source, "references", "source.references", schema, errors)

    roles = _validate_list_field(vc, "roles", "roles", schema, errors)
    states = _validate_list_field(vc, "states", "states", schema, errors)
    transitions = _validate_list_field(
        vc, "transitions", "transitions", schema, errors
    )
    guards = _validate_list_field(vc, "guards", "guards", schema, errors)

    if states is not None:
        for index, state in enumerate(states):
            path = f"states[{index}]"
            if not isinstance(state, dict):
                continue
            _validate_object(state, path, "state", schema, errors)
            if "name" in state:
                _validate_field(
                    state["name"], f"{path}.name", "states[].name", schema, errors
                )
            if "kind" in state:
                _validate_field(
                    state["kind"], f"{path}.kind", "states[].kind", schema, errors
                )

    if transitions is not None:
        for index, transition in enumerate(transitions):
            path = f"transitions[{index}]"
            if not isinstance(transition, dict):
                continue
            _validate_object(transition, path, "transition", schema, errors)
            for key in ("from", "on", "expected", "to", "guard_ref"):
                if key in transition:
                    _validate_field(
                        transition[key],
                        f"{path}.{key}",
                        f"transitions[].{key}",
                        schema,
                        errors,
                    )

    if guards is not None:
        for index, guard in enumerate(guards):
            path = f"guards[{index}]"
            if not isinstance(guard, dict):
                continue
            _validate_object(guard, path, "guard", schema, errors)
            for key in ("id", "description"):
                if key in guard:
                    _validate_field(
                        guard[key], f"{path}.{key}", f"guards[].{key}", schema, errors
                    )

    mutation = _child_object(vc, "mutation", "mutation", schema, errors)
    if mutation is not None:
        for key in ("strategy", "witness_ref"):
            if key in mutation:
                _validate_field(
                    mutation[key], f"mutation.{key}", f"mutation.{key}", schema, errors
                )
        points = _validate_list_field(
            mutation, "points", "mutation.points", schema, errors
        )
        if points is not None:
            for index, point in enumerate(points):
                path = f"mutation.points[{index}]"
                if not isinstance(point, dict):
                    continue
                _validate_object(point, path, "mutation_point", schema, errors)
                for key in ("name", "placeholder", "type", "constraint"):
                    if key in point:
                        _validate_field(
                            point[key],
                            f"{path}.{key}",
                            f"mutation.points[].{key}",
                            schema,
                            errors,
                        )

    oracle = _child_object(vc, "oracle", "oracle", schema, errors)
    if oracle is not None:
        for key in ("memory_safety", "bug_candidate", "fixed_or_safe"):
            _validate_list_field(oracle, key, f"oracle.{key}", schema, errors)
        violation = _child_object(
            oracle, "contract_violation", "contract_violation", schema, errors,
            path="oracle.contract_violation"
        )
        if violation is not None:
            for key in ("relation", "independent_of_generator"):
                if key in violation:
                    _validate_field(
                        violation[key],
                        f"oracle.contract_violation.{key}",
                        f"oracle.contract_violation.{key}",
                        schema,
                        errors,
                    )

    effect = _child_object(vc, "effect", "effect", schema, errors)
    if effect is not None:
        if "summary" in effect:
            _validate_field(
                effect["summary"], "effect.summary", "effect.summary", schema, errors
            )
        _validate_list_field(effect, "sinks", "effect.sinks", schema, errors)

    fidelity = _child_object(vc, "fidelity", "fidelity", schema, errors)
    if fidelity is not None:
        _validate_list_field(
            fidelity, "target_states", "fidelity.target_states", schema, errors
        )
        if "divergence_required" in fidelity:
            _validate_field(
                fidelity["divergence_required"],
                "fidelity.divergence_required",
                "fidelity.divergence_required",
                schema,
                errors,
            )

    provenance = _child_object(vc, "provenance", "provenance", schema, errors)
    if provenance is not None:
        if "miner" in provenance:
            _validate_field(
                provenance["miner"],
                "provenance.miner",
                "provenance.miner",
                schema,
                errors,
            )
        _validate_list_field(
            provenance, "derived_from", "provenance.derived_from", schema, errors
        )
        if "human_reviewed" in provenance:
            _validate_field(
                provenance["human_reviewed"],
                "provenance.human_reviewed",
                "provenance.human_reviewed",
                schema,
                errors,
            )

    _validate_references(vc, roles, states, transitions, guards, errors)
    _validate_transition_conditions(transitions, errors)
    _validate_core_transition(transitions, errors)
    _validate_uniqueness(roles, states, guards, errors)
    _validate_witness(vc, Path(repo_root) if repo_root else _DEFAULT_REPO_ROOT, errors)
    return _stable_errors(errors)


def load_and_validate_vc(
    path: str | Path, repo_root: str | Path | None = None
) -> tuple[Any, list[str]]:
    """Load a VC file and return the data together with all validation errors."""

    vc = load_vc(path)
    return vc, validate_vc(vc, repo_root=repo_root)


def validate_vc_or_raise(vc: Any, repo_root: str | Path | None = None) -> None:
    """Raise one aggregate exception when a VC is invalid."""

    errors = validate_vc(vc, repo_root=repo_root)
    if errors:
        raise VCValidationError(errors)


def _load_schema_definition() -> Mapping[str, Any]:
    try:
        data = yaml.safe_load(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RuntimeError(f"cannot load bundled VC schema: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("bundled VC schema must be a mapping")
    return data


def _validate_object(
    value: Any,
    path: str,
    object_name: str,
    schema: Mapping[str, Any],
    errors: list[str],
) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object, got {_type_name(value)}")
        return False
    spec = schema["objects"][object_name]
    required = set(spec.get("required", []))
    allowed = required | set(spec.get("optional", []))
    for key in sorted(required - set(value)):
        errors.append(f"{_path(path, key)}: required field missing")
    for key in sorted(set(value) - allowed, key=str):
        errors.append(f"{_path(path, str(key))}: unknown field")
    return True


def _child_object(
    parent: Mapping[str, Any],
    key: str,
    object_name: str,
    schema: Mapping[str, Any],
    errors: list[str],
    path: str | None = None,
) -> dict[str, Any] | None:
    if key not in parent:
        return None
    value = parent[key]
    object_path = path or key
    if not _validate_object(value, object_path, object_name, schema, errors):
        return None
    return value


def _validate_list_field(
    parent: Mapping[str, Any],
    key: str,
    list_name: str,
    schema: Mapping[str, Any],
    errors: list[str],
) -> list[Any] | None:
    if key not in parent:
        return None
    value = parent[key]
    spec = schema["lists"][list_name]
    if not isinstance(value, list):
        errors.append(f"{list_name}: expected list, got {_type_name(value)}")
        return None
    minimum = spec.get("min_items", 0)
    if len(value) < minimum:
        errors.append(f"{list_name}: expected at least {minimum} item(s)")
    item_type = spec["item_type"]
    vocabulary = schema.get("enums", {}).get(spec.get("enum", ""))
    for index, item in enumerate(value):
        item_path = f"{list_name}[{index}]"
        if not _matches_type(item, item_type):
            errors.append(
                f"{item_path}: expected {item_type}, got {_type_name(item)}"
            )
        elif vocabulary is not None and item not in vocabulary:
            errors.append(f"{item_path}: unknown value {item!r}")
    return value


def _validate_field(
    value: Any,
    path: str,
    field_name: str,
    schema: Mapping[str, Any],
    errors: list[str],
) -> None:
    spec = schema["fields"][field_name]
    expected_type = spec["type"]
    if not _matches_type(value, expected_type):
        errors.append(f"{path}: expected {expected_type}, got {_type_name(value)}")
        return
    if "literal" in spec and value != spec["literal"]:
        errors.append(f"{path}: expected literal {spec['literal']!r}, got {value!r}")
    if "pattern" in spec and re.fullmatch(spec["pattern"], value) is None:
        errors.append(f"{path}: does not match {spec['pattern']!r}")
    if spec.get("lowercase") and value != value.lower():
        errors.append(f"{path}: must be lowercase")
    vocabulary = schema.get("enums", {}).get(spec.get("enum", ""))
    if vocabulary is not None and value not in vocabulary:
        errors.append(f"{path}: unknown value {value!r}")


def _validate_references(
    vc: Mapping[str, Any],
    roles: list[Any] | None,
    states: list[Any] | None,
    transitions: list[Any] | None,
    guards: list[Any] | None,
    errors: list[str],
) -> None:
    declared_roles = {item for item in roles or [] if isinstance(item, str)}
    declared_states = {
        item.get("name")
        for item in states or []
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    declared_guards = {
        item.get("id")
        for item in guards or []
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for index, transition in enumerate(transitions or []):
        if not isinstance(transition, dict):
            continue
        for key, declared, label in (
            ("from", declared_states, "state"),
            ("to", declared_states, "state"),
            ("on", declared_roles, "role"),
            ("guard_ref", declared_guards, "guard"),
        ):
            value = transition.get(key)
            if isinstance(value, str) and value not in declared:
                errors.append(
                    f"transitions[{index}].{key}: undeclared {label} {value!r}"
                )
    fidelity = vc.get("fidelity")
    if isinstance(fidelity, dict):
        targets = fidelity.get("target_states")
        if isinstance(targets, list):
            for index, target in enumerate(targets):
                if isinstance(target, str) and target not in declared_states:
                    errors.append(
                        f"fidelity.target_states[{index}]: undeclared state {target!r}"
                    )


def _validate_transition_conditions(
    transitions: list[Any] | None, errors: list[str]
) -> None:
    for index, transition in enumerate(transitions or []):
        if not isinstance(transition, dict):
            continue
        expected = transition.get("expected")
        if expected == "forbidden":
            if "to" in transition:
                errors.append(
                    f"transitions[{index}].to: forbidden when expected='forbidden'"
                )
            if "guard_ref" in transition:
                errors.append(
                    f"transitions[{index}].guard_ref: forbidden unless expected='allowed_with_guard'"
                )
        elif expected == "required":
            if "to" not in transition:
                errors.append(
                    f"transitions[{index}].to: required when expected='required'"
                )
            if "guard_ref" in transition:
                errors.append(
                    f"transitions[{index}].guard_ref: forbidden unless expected='allowed_with_guard'"
                )
        elif expected == "allowed_with_guard":
            if "to" not in transition:
                errors.append(
                    f"transitions[{index}].to: required when expected='allowed_with_guard'"
                )
            if "guard_ref" not in transition:
                errors.append(
                    f"transitions[{index}].guard_ref: required when expected='allowed_with_guard'"
                )


def _validate_core_transition(
    transitions: list[Any] | None, errors: list[str]
) -> None:
    if not any(
        isinstance(item, dict)
        and item.get("expected") in {"forbidden", "required"}
        for item in transitions or []
    ):
        errors.append(
            "transitions: requires at least one expected='forbidden' or expected='required'"
        )


def _validate_uniqueness(
    roles: list[Any] | None,
    states: list[Any] | None,
    guards: list[Any] | None,
    errors: list[str],
) -> None:
    role_values = [item for item in roles or [] if isinstance(item, str)]
    for value in sorted(value for value, count in Counter(role_values).items() if count > 1):
        errors.append(f"roles: duplicate role {value!r}")

    _append_duplicate_object_errors(states, "name", "states", "state name", errors)
    _append_duplicate_object_errors(guards, "id", "guards", "guard id", errors)


def _append_duplicate_object_errors(
    items: list[Any] | None,
    key: str,
    path: str,
    label: str,
    errors: list[str],
) -> None:
    values = [
        item.get(key)
        for item in items or []
        if isinstance(item, dict) and isinstance(item.get(key), str)
    ]
    for value in sorted(value for value, count in Counter(values).items() if count > 1):
        errors.append(f"{path}: duplicate {label} {value!r}")


def _validate_witness(
    vc: Mapping[str, Any], repo_root: Path, errors: list[str]
) -> None:
    mutation = vc.get("mutation")
    if not isinstance(mutation, dict):
        return
    witness_ref = mutation.get("witness_ref")
    if not isinstance(witness_ref, str):
        return
    witness_path = Path(witness_ref)
    if witness_path.is_absolute():
        errors.append("mutation.witness_ref: must be a repo-relative path")
        return
    root = repo_root.resolve()
    resolved = (root / witness_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        errors.append("mutation.witness_ref: path escapes repository root")
        return
    if not resolved.is_file():
        errors.append(
            f"mutation.witness_ref: existing regular file required: {witness_ref!r}"
        )


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return type(value) is bool
    if expected == "object":
        return isinstance(value, dict)
    if expected == "list":
        return isinstance(value, list)
    raise RuntimeError(f"unknown bundled schema type: {expected}")


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    return type(value).__name__


def _path(parent: str, key: str) -> str:
    return key if parent == "$" else f"{parent}.{key}"


def _stable_errors(errors: list[str]) -> list[str]:
    return sorted(dict.fromkeys(errors))
