"""Strict observation-only Buggy/Fixed divergence artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from contract_miner.roles import OBSERVABLE_ROLES, VALUE_TYPES


_ID = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SCHEMA_PATH = Path(__file__).with_name("divergence.schema.yaml")
COMPARISONS = frozenset({"equal", "not_equal", "only_buggy", "only_fixed", "trace_terminated"})


class DivergenceValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("invalid divergence:\n" + "\n".join(f"- {item}" for item in errors))


def load_divergence(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def validate_divergence(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    required = {"schema_version", "divergence_id", "source_pair", "intervention_refs", "evidence_refs", "deltas", "provenance"}
    _keys(value, "$", required, set(), errors)
    if value.get("schema_version") != "cipherlens.divergence.v0_1":
        errors.append("schema_version: expected cipherlens.divergence.v0_1")
    _identifier(value.get("divergence_id"), "divergence_id", errors)
    pair = _object(value.get("source_pair"), "source_pair", {"library", "buggy_revision", "fixed_revision", "pair_kind"}, set(), errors)
    if pair:
        for key in ("library", "buggy_revision", "fixed_revision"):
            _string(pair.get(key), f"source_pair.{key}", errors)
        if pair.get("pair_kind") != "same_library_fix":
            errors.append("source_pair.pair_kind: only same_library_fix is supported")
        if isinstance(pair.get("library"), str) and pair["library"] != pair["library"].lower():
            errors.append("source_pair.library: must be lowercase")
    _string_list(value.get("intervention_refs"), "intervention_refs", errors)
    _string_list(value.get("evidence_refs"), "evidence_refs", errors)
    deltas = _list(value.get("deltas"), "deltas", 1, errors)
    seen: set[str] = set()
    for index, item in enumerate(deltas):
        path = f"deltas[{index}]"
        delta = _object(item, path, {"delta_id", "step_ref", "semantic_role", "value_type", "buggy", "fixed", "comparison", "source_refs"}, set(), errors)
        if not delta:
            continue
        _identifier(delta.get("delta_id"), f"{path}.delta_id", errors)
        if delta.get("delta_id") in seen:
            errors.append(f"{path}.delta_id: duplicate")
        seen.add(delta.get("delta_id"))
        _string(delta.get("step_ref"), f"{path}.step_ref", errors)
        _enum(delta.get("semantic_role"), OBSERVABLE_ROLES, f"{path}.semantic_role", errors)
        _enum(delta.get("value_type"), VALUE_TYPES, f"{path}.value_type", errors)
        _enum(delta.get("comparison"), COMPARISONS, f"{path}.comparison", errors)
        _string_list(delta.get("source_refs"), f"{path}.source_refs", errors)
        for side in ("buggy", "fixed"):
            fact = _object(delta.get(side), f"{path}.{side}", {"present"}, {"value"}, errors)
            if fact:
                if type(fact.get("present")) is not bool:
                    errors.append(f"{path}.{side}.present: expected boolean")
                if fact.get("present") and "value" not in fact:
                    errors.append(f"{path}.{side}.value: required when present")
                if not fact.get("present") and "value" in fact:
                    errors.append(f"{path}.{side}.value: forbidden when missing")
    provenance = _object(value.get("provenance"), "provenance", {"producer", "source_refs"}, set(), errors)
    if provenance:
        _string(provenance.get("producer"), "provenance.producer", errors)
        _string_list(provenance.get("source_refs"), "provenance.source_refs", errors)
    return sorted(dict.fromkeys(errors))


def validate_divergence_or_raise(value: Any) -> None:
    errors = validate_divergence(value)
    if errors:
        raise DivergenceValidationError(errors)


def canonical_divergence_bytes(value: Mapping[str, Any]) -> bytes:
    validate_divergence_or_raise(value)
    return yaml.safe_dump(dict(value), allow_unicode=True, default_flow_style=False, sort_keys=True).encode("utf-8")


def divergence_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_divergence_bytes(value)).hexdigest()


def dump_divergence(value: Mapping[str, Any], path: str | Path) -> None:
    Path(path).write_bytes(canonical_divergence_bytes(value))


def _object(value: Any, path: str, required: set[str], optional: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, required, optional, errors)
    return value


def _keys(value: Mapping[str, Any], path: str, required: set[str], optional: set[str], errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{path}.{key}: required field missing")
    for key in sorted(set(value) - required - optional):
        errors.append(f"{path}.{key}: unknown field")


def _list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _string_list(value: Any, path: str, errors: list[str]) -> None:
    for index, item in enumerate(_list(value, path, 0, errors)):
        _string(item, f"{path}[{index}]", errors)


def _string(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _identifier(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        errors.append(f"{path}: expected UPPER_SNAKE identifier")


def _enum(value: Any, allowed: Any, path: str, errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{path}: unknown value {value!r}")
