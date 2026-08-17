"""Load, validate, and canonically serialize CipherLens VC documents."""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from contract_miner.roles import (
    INTERVENTION_KINDS, OBJECT_ROLES, OPERATION_ROLES,
    PRECONDITION_PREDICATES, STATE_KINDS, VALUE_TYPES,
)

_SCHEMA_PATH = Path(__file__).with_name("vc.schema.yaml")
_V02_SCHEMA_PATH = Path(__file__).with_name("vc.v0_2.schema.yaml")
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parent.parent
_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_LOCAL_ID = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _validate_v02(vc: Any, repo_root: str | Path | None = None) -> list[str]:
    """Validate the frozen read-only v0.2 representation."""

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
        data = yaml.safe_load(_V02_SCHEMA_PATH.read_text(encoding="utf-8"))
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


def validate_vc(vc: Any, repo_root: str | Path | None = None) -> list[str]:
    """Dispatch validation by the explicit schema version."""
    if not isinstance(vc, dict):
        return [f"$: expected object, got {_type_name(vc)}"]
    version = vc.get("schema_version")
    if version == "cipherlens.vc.v0_2" or any(
        key in vc for key in ("roles", "mutation", "oracle", "fidelity")
    ):
        return _validate_v02(vc, repo_root=repo_root)
    if version == "cipherlens.vc.v0_3":
        return _validate_v03(vc, Path(repo_root) if repo_root else _DEFAULT_REPO_ROOT)
    return [f"schema_version: unsupported version {version!r}"]


def canonical_vc_bytes(vc: Mapping[str, Any]) -> bytes:
    """Return a stable UTF-8 YAML representation."""
    return yaml.safe_dump(dict(vc), allow_unicode=True, default_flow_style=False, sort_keys=True).encode("utf-8")


def dump_vc(vc: Mapping[str, Any], path: str | Path) -> None:
    """Validate and write one canonical v0.3 Contract document."""
    validate_vc_or_raise(vc)
    Path(path).write_bytes(canonical_vc_bytes(vc))


def contract_digest(vc: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_vc_bytes(vc)).hexdigest()


def _load_v03_schema() -> Mapping[str, Any]:
    data = yaml.safe_load(_SCHEMA_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != "cipherlens.vc.v0_3":
        raise RuntimeError("invalid bundled v0.3 schema")
    return data


def _validate_v03(vc: Mapping[str, Any], repo_root: Path) -> list[str]:
    enums = _load_v03_schema()["enums"]
    errors: list[str] = []
    required_top = {"contract_id", "schema_version", "contract_family", "source", "context", "intervention", "execution", "expected_relation", "observable_evidence", "provenance"}
    _v3_keys(vc, "$", required_top, set(), errors)
    _v3_match(vc.get("contract_id"), "contract_id", _ID, errors)
    _v3_literal(vc.get("schema_version"), "schema_version", "cipherlens.vc.v0_3", errors)
    _v3_enum(vc.get("contract_family"), "contract_family", enums["contract_families"], errors)

    source = _v3_object(vc.get("source"), "source", {"pattern_id", "library", "buggy_revision", "fixed_revision"}, {"references"}, errors)
    if source:
        for key in ("pattern_id", "library", "buggy_revision", "fixed_revision"):
            _v3_string(source.get(key), f"source.{key}", errors)
        if isinstance(source.get("library"), str) and source["library"] != source["library"].lower():
            errors.append("source.library: must be lowercase")
        _v3_string_list(source.get("references", []), "source.references", errors)

    context = _v3_object(vc.get("context"), "context", {"objects", "states", "preconditions"}, set(), errors)
    objects = _v3_list(context.get("objects") if context else None, "context.objects", 1, errors)
    states = _v3_list(context.get("states") if context else None, "context.states", 0, errors)
    preconditions = _v3_list(context.get("preconditions") if context else None, "context.preconditions", 0, errors)
    for index, item in enumerate(objects):
        path = f"context.objects[{index}]"
        obj = _v3_object(item, path, {"object_id", "semantic_role", "value_type"}, set(), errors)
        if obj:
            _v3_local_id(obj.get("object_id"), f"{path}.object_id", errors)
            _v3_enum(obj.get("semantic_role"), f"{path}.semantic_role", OBJECT_ROLES, errors)
            _v3_enum(obj.get("value_type"), f"{path}.value_type", VALUE_TYPES, errors)
    for index, item in enumerate(states):
        path = f"context.states[{index}]"
        state = _v3_object(item, path, {"state_id", "kind"}, set(), errors)
        if state:
            _v3_local_id(state.get("state_id"), f"{path}.state_id", errors)
            _v3_enum(state.get("kind"), f"{path}.kind", STATE_KINDS, errors)
    for index, item in enumerate(preconditions):
        path = f"context.preconditions[{index}]"
        pre = _v3_object(item, path, {"precondition_id", "predicate_id", "operand_refs"}, set(), errors)
        if pre:
            _v3_local_id(pre.get("precondition_id"), f"{path}.precondition_id", errors)
            _v3_enum(pre.get("predicate_id"), f"{path}.predicate_id", PRECONDITION_PREDICATES, errors)
            _v3_string_list(pre.get("operand_refs"), f"{path}.operand_refs", errors)

    intervention = _v3_object(vc.get("intervention"), "intervention", {"actions"}, set(), errors)
    actions = _v3_list(intervention.get("actions") if intervention else None, "intervention.actions", 1, errors)
    for index, item in enumerate(actions):
        path = f"intervention.actions[{index}]"
        action = _v3_object(item, path, {"action_id", "kind", "target_ref", "parameters", "evidence_refs"}, set(), errors)
        if not action:
            continue
        _v3_local_id(action.get("action_id"), f"{path}.action_id", errors)
        _v3_enum(action.get("kind"), f"{path}.kind", INTERVENTION_KINDS, errors)
        _v3_string(action.get("target_ref"), f"{path}.target_ref", errors)
        _v3_string_list(action.get("evidence_refs"), f"{path}.evidence_refs", errors)
        params = _v3_list(action.get("parameters"), f"{path}.parameters", 0, errors)
        for pindex, value in enumerate(params):
            ppath = f"{path}.parameters[{pindex}]"
            param = _v3_object(value, ppath, {"name", "value_type"}, {"value", "constraint_id"}, errors)
            if param:
                _v3_string(param.get("name"), f"{ppath}.name", errors)
                _v3_enum(param.get("value_type"), f"{ppath}.value_type", VALUE_TYPES, errors)
                if "constraint_id" in param:
                    _v3_string(param["constraint_id"], f"{ppath}.constraint_id", errors)
                if "value" in param and isinstance(param["value"], (dict, list)):
                    errors.append(f"{ppath}.value: scalar required")

    execution = _v3_object(vc.get("execution"), "execution", {"steps"}, set(), errors)
    steps = _v3_list(execution.get("steps") if execution else None, "execution.steps", 1, errors)
    for index, item in enumerate(steps):
        path = f"execution.steps[{index}]"
        step = _v3_object(item, path, {"step_id", "role", "target_ref", "precondition_refs", "input_refs"}, {"pre_state_ref"}, errors)
        if step:
            _v3_local_id(step.get("step_id"), f"{path}.step_id", errors)
            _v3_enum(step.get("role"), f"{path}.role", OPERATION_ROLES, errors)
            _v3_string(step.get("target_ref"), f"{path}.target_ref", errors)
            _v3_string_list(step.get("precondition_refs"), f"{path}.precondition_refs", errors)
            _v3_string_list(step.get("input_refs"), f"{path}.input_refs", errors)
            if "pre_state_ref" in step:
                _v3_string(step["pre_state_ref"], f"{path}.pre_state_ref", errors)

    expected = _v3_object(vc.get("expected_relation"), "expected_relation", {"aggregation", "relations"}, {"summary"}, errors)
    if expected:
        _v3_literal(expected.get("aggregation"), "expected_relation.aggregation", "all_of", errors)
        if "summary" in expected:
            _v3_string(expected["summary"], "expected_relation.summary", errors)
    relations = _v3_list(expected.get("relations") if expected else None, "expected_relation.relations", 1, errors)
    for index, item in enumerate(relations):
        _validate_v03_relation(item, index, enums, errors)

    observable_block = _v3_object(vc.get("observable_evidence"), "observable_evidence", {"observables"}, set(), errors)
    observables = _v3_list(observable_block.get("observables") if observable_block else None, "observable_evidence.observables", 1, errors)
    for index, item in enumerate(observables):
        _validate_v03_observable(item, index, enums, errors)

    provenance = _v3_object(vc.get("provenance"), "provenance", {"producer", "evidence", "field_origins", "human_review"}, set(), errors)
    evidence: list[Any] = []
    origins: list[Any] = []
    if provenance:
        producer = _v3_object(provenance.get("producer"), "provenance.producer", {"name", "version", "mode"}, set(), errors)
        if producer:
            _v3_string(producer.get("name"), "provenance.producer.name", errors)
            _v3_string(producer.get("version"), "provenance.producer.version", errors)
            _v3_enum(producer.get("mode"), "provenance.producer.mode", enums["producer_modes"], errors)
        evidence = _v3_list(provenance.get("evidence"), "provenance.evidence", 1, errors)
        origins = _v3_list(provenance.get("field_origins"), "provenance.field_origins", 1, errors)
        review = _v3_object(provenance.get("human_review"), "provenance.human_review", {"status"}, set(), errors)
        if review:
            _v3_enum(review.get("status"), "provenance.human_review.status", enums["review_statuses"], errors)
    for index, item in enumerate(evidence):
        path = f"provenance.evidence[{index}]"
        ev = _v3_object(item, path, {"evidence_id", "kind", "path", "sha256"}, set(), errors)
        if ev:
            _v3_local_id(ev.get("evidence_id"), f"{path}.evidence_id", errors)
            _v3_enum(ev.get("kind"), f"{path}.kind", enums["evidence_kinds"], errors)
            _v3_string(ev.get("path"), f"{path}.path", errors)
            _v3_match(ev.get("sha256"), f"{path}.sha256", _SHA256, errors)
            _v3_evidence_path(ev, path, repo_root, errors)
    for index, item in enumerate(origins):
        path = f"provenance.field_origins[{index}]"
        origin = _v3_object(item, path, {"field_path", "source_refs", "method", "rule_id"}, set(), errors)
        if origin:
            _v3_string(origin.get("field_path"), f"{path}.field_path", errors)
            _v3_string_list(origin.get("source_refs"), f"{path}.source_refs", errors)
            _v3_enum(origin.get("method"), f"{path}.method", enums["derivation_methods"], errors)
            _v3_string(origin.get("rule_id"), f"{path}.rule_id", errors)

    _validate_v03_references(objects, states, preconditions, actions, steps, relations, observables, evidence, origins, errors)
    unique_groups = (
        (objects, "object_id", "context.objects"),
        (states, "state_id", "context.states"),
        (preconditions, "precondition_id", "context.preconditions"),
        (actions, "action_id", "intervention.actions"),
        (steps, "step_id", "execution.steps"),
        (relations, "relation_id", "expected_relation.relations"),
        (observables, "observable_id", "observable_evidence.observables"),
        (evidence, "evidence_id", "provenance.evidence"),
    )
    for items, key, path in unique_groups:
        _v3_unique(items, key, path, errors)
    return _stable_errors(errors)


def _validate_v03_relation(item: Any, index: int, enums: Mapping[str, Any], errors: list[str]) -> None:
    path = f"expected_relation.relations[{index}]"
    rel = _v3_object(item, path, {"relation_id", "type", "criticality", "operands"}, set(), errors)
    if not rel:
        return
    _v3_local_id(rel.get("relation_id"), f"{path}.relation_id", errors)
    _v3_enum(rel.get("type"), f"{path}.type", enums["relation_types"], errors)
    _v3_enum(rel.get("criticality"), f"{path}.criticality", enums["criticalities"], errors)
    relation_type = rel.get("type")
    specs = {
        "outcome_requirement": {"outcome_ref", "expectation"},
        "full_consumption_on_success": {"outcome_ref", "consumed_length_ref", "input_length_ref"},
        "output_preserved_on_failure": {"outcome_ref", "before_ref", "after_ref"},
        "state_invariant": {"invariant_id", "buffer_present_ref", "length_ref"},
        "transition_constraint": {"outcome_ref", "state_before_ref", "state_after_ref", "expected_state_ref", "policy"},
        "failure_propagation": {"inner_outcome_ref", "outer_outcome_ref"},
        "no_fatal_event": {"fatal_event_ref"},
    }
    operands = rel.get("operands")
    if relation_type in specs:
        operands = _v3_object(operands, f"{path}.operands", specs[relation_type], set(), errors)
    elif not isinstance(operands, dict):
        errors.append(f"{path}.operands: expected object")
        return
    if not operands:
        return
    for key, value in operands.items():
        if key.endswith("_ref"):
            _v3_string(value, f"{path}.operands.{key}", errors)
    if relation_type == "outcome_requirement":
        _v3_enum(operands.get("expectation"), f"{path}.operands.expectation", enums["outcomes"], errors)
    elif relation_type == "state_invariant":
        _v3_enum(operands.get("invariant_id"), f"{path}.operands.invariant_id", enums["invariant_ids"], errors)
    elif relation_type == "transition_constraint":
        _v3_enum(operands.get("policy"), f"{path}.operands.policy", enums["transition_policies"], errors)


def _validate_v03_observable(item: Any, index: int, enums: Mapping[str, Any], errors: list[str]) -> None:
    path = f"observable_evidence.observables[{index}]"
    required = {"observable_id", "semantic_role", "source", "value_type", "requirement", "extraction", "provenance_refs"}
    obs = _v3_object(item, path, required, set(), errors)
    if not obs:
        return
    _v3_local_id(obs.get("observable_id"), f"{path}.observable_id", errors)
    _v3_enum(obs.get("semantic_role"), f"{path}.semantic_role", enums["observable_roles"], errors)
    _v3_enum(obs.get("value_type"), f"{path}.value_type", enums["value_types"], errors)
    _v3_enum(obs.get("requirement"), f"{path}.requirement", enums["observable_requirements"], errors)
    _v3_string_list(obs.get("provenance_refs"), f"{path}.provenance_refs", errors)
    source = _v3_object(obs.get("source"), f"{path}.source", {"phase"}, {"step_ref"}, errors)
    if source:
        _v3_enum(source.get("phase"), f"{path}.source.phase", enums["observable_phases"], errors)
        if source.get("phase") != "process_end" and "step_ref" not in source:
            errors.append(f"{path}.source.step_ref: required unless phase='process_end'")
        if "step_ref" in source:
            _v3_string(source["step_ref"], f"{path}.source.step_ref", errors)
    extraction = _v3_object(obs.get("extraction"), f"{path}.extraction", {"kind", "field"}, {"rule_id"}, errors)
    if extraction:
        kind = extraction.get("kind")
        _v3_enum(kind, f"{path}.extraction.kind", enums["extraction_kinds"], errors)
        _v3_string(extraction.get("field"), f"{path}.extraction.field", errors)
        if kind in {"normalized_return", "derived"} and "rule_id" not in extraction:
            errors.append(f"{path}.extraction.rule_id: required for {kind}")
        if "rule_id" in extraction:
            registry = enums["normalization_rules"] if kind == "normalized_return" else enums["derived_rules"] if kind == "derived" else []
            _v3_enum(extraction["rule_id"], f"{path}.extraction.rule_id", registry, errors)


def _validate_v03_references(objects: list[Any], states: list[Any], preconditions: list[Any], actions: list[Any], steps: list[Any], relations: list[Any], observables: list[Any], evidence: list[Any], origins: list[Any], errors: list[str]) -> None:
    object_ids = _ids(objects, "object_id")
    state_ids = _ids(states, "state_id")
    pre_ids = _ids(preconditions, "precondition_id")
    action_ids = _ids(actions, "action_id")
    step_ids = _ids(steps, "step_id")
    observable_ids = _ids(observables, "observable_id")
    evidence_ids = _ids(evidence, "evidence_id")
    for index, pre in enumerate(preconditions):
        if isinstance(pre, dict):
            _check_refs(pre.get("operand_refs"), object_ids, f"context.preconditions[{index}].operand_refs", errors)
    for index, action in enumerate(actions):
        if isinstance(action, dict):
            _check_ref(action.get("target_ref"), object_ids, f"intervention.actions[{index}].target_ref", errors)
            _check_refs(action.get("evidence_refs"), evidence_ids, f"intervention.actions[{index}].evidence_refs", errors)
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        _check_ref(step.get("target_ref"), object_ids, f"execution.steps[{index}].target_ref", errors)
        _check_refs(step.get("input_refs"), object_ids | action_ids, f"execution.steps[{index}].input_refs", errors)
        _check_refs(step.get("precondition_refs"), pre_ids, f"execution.steps[{index}].precondition_refs", errors)
        if "pre_state_ref" in step:
            _check_ref(step.get("pre_state_ref"), state_ids, f"execution.steps[{index}].pre_state_ref", errors)
    for index, obs in enumerate(observables):
        if not isinstance(obs, dict):
            continue
        source = obs.get("source")
        if isinstance(source, dict) and "step_ref" in source:
            _check_ref(source.get("step_ref"), step_ids, f"observable_evidence.observables[{index}].source.step_ref", errors)
        _check_refs(obs.get("provenance_refs"), evidence_ids, f"observable_evidence.observables[{index}].provenance_refs", errors)
    for index, rel in enumerate(relations):
        if not isinstance(rel, dict) or not isinstance(rel.get("operands"), dict):
            continue
        for key, value in rel["operands"].items():
            path = f"expected_relation.relations[{index}].operands.{key}"
            if key == "expected_state_ref":
                _check_ref(value, state_ids, path, errors)
            elif key.endswith("_ref"):
                _check_ref(value, observable_ids, path, errors)
    for index, origin in enumerate(origins):
        if isinstance(origin, dict):
            _check_refs(origin.get("source_refs"), evidence_ids, f"provenance.field_origins[{index}].source_refs", errors)


def _v3_object(value: Any, path: str, required: set[str], optional: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object, got {_type_name(value)}")
        return None
    _v3_keys(value, path, required, optional, errors)
    return value


def _v3_keys(value: Mapping[str, Any], path: str, required: set[str], optional: set[str], errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{_path(path, key)}: required field missing")
    for key in sorted(set(value) - required - optional, key=str):
        errors.append(f"{_path(path, str(key))}: unknown field")


def _v3_list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list, got {_type_name(value)}")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _v3_string(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _v3_string_list(value: Any, path: str, errors: list[str]) -> None:
    items = _v3_list(value, path, 0, errors)
    for index, item in enumerate(items):
        _v3_string(item, f"{path}[{index}]", errors)


def _v3_enum(value: Any, path: str, allowed: Any, errors: list[str]) -> None:
    if not isinstance(value, str) or value not in set(allowed):
        errors.append(f"{path}: unknown value {value!r}")


def _v3_literal(value: Any, path: str, expected: Any, errors: list[str]) -> None:
    if value != expected:
        errors.append(f"{path}: expected literal {expected!r}, got {value!r}")


def _v3_match(value: Any, path: str, pattern: re.Pattern[str], errors: list[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        errors.append(f"{path}: does not match {pattern.pattern!r}")


def _v3_local_id(value: Any, path: str, errors: list[str]) -> None:
    _v3_match(value, path, _LOCAL_ID, errors)


def _v3_unique(items: list[Any], key: str, path: str, errors: list[str]) -> None:
    values = [item.get(key) for item in items if isinstance(item, dict) and isinstance(item.get(key), str)]
    for value, count in Counter(values).items():
        if count > 1:
            errors.append(f"{path}: duplicate {key} {value!r}")


def _ids(items: list[Any], key: str) -> set[str]:
    return {item[key] for item in items if isinstance(item, dict) and isinstance(item.get(key), str)}


def _check_ref(value: Any, declared: set[str], path: str, errors: list[str]) -> None:
    if isinstance(value, str) and value not in declared:
        errors.append(f"{path}: dangling reference {value!r}")


def _check_refs(values: Any, declared: set[str], path: str, errors: list[str]) -> None:
    if isinstance(values, list):
        for index, value in enumerate(values):
            _check_ref(value, declared, f"{path}[{index}]", errors)


def _v3_evidence_path(evidence: Mapping[str, Any], path: str, repo_root: Path, errors: list[str]) -> None:
    raw = evidence.get("path")
    digest = evidence.get("sha256")
    if not isinstance(raw, str):
        return
    candidate = Path(raw)
    if candidate.is_absolute():
        errors.append(f"{path}.path: must be repo-relative")
        return
    root = repo_root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        errors.append(f"{path}.path: path escapes repository root")
        return
    if not resolved.is_file():
        errors.append(f"{path}.path: existing regular file required: {raw!r}")
        return
    if isinstance(digest, str) and _SHA256.fullmatch(digest):
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f"{path}.sha256: digest mismatch")
