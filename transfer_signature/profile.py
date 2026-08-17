"""Strict multi-subject TargetSemanticProfile validation."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from transfer_signature.model import (
    Assertion,
    EpistemicStatus,
    FactCoverage,
    PROFILE_SCHEMA_VERSION,
    SchemaValidationError,
)
from transfer_signature.registry import FACT_PARAMETER_KEYS, validate_fact_parameters
from contract_miner.roles import OBJECT_ROLES


_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SUBJECT_KINDS = frozenset(
    {"API", "API_GROUP", "WRAPPER", "INTERFACE", "OBJECT_MODEL", "CALL_SURFACE", "OBJECT", "OBSERVATION_CHANNEL"}
)
_EVIDENCE_KINDS = frozenset(
    {"official_doc", "source", "test", "runtime_probe", "adapter_recipe", "api_card", "rag", "llm_proposal", "manual_review", "test_fixture"}
)
_DETERMINISTIC_EVIDENCE = frozenset(
    {"official_doc", "source", "test", "runtime_probe", "manual_review", "test_fixture"}
)


def load_profile(path: str | Path) -> Any:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def validate_profile(value: Any, repo_root: str | Path | None = None) -> list[str]:
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    required = {"schema_version", "profile_id", "target_scope", "subjects", "facts", "evidence"}
    _keys(value, "$", required, errors)
    if value.get("schema_version") != PROFILE_SCHEMA_VERSION:
        errors.append(f"schema_version: expected literal {PROFILE_SCHEMA_VERSION!r}")
    _match(value.get("profile_id"), "profile_id", _ID, errors)

    scope = _object(value.get("target_scope"), "target_scope", {"library", "version", "surface_ref"}, errors)
    surface_ref = None
    if scope:
        for key in ("library", "version"):
            _nonempty_string(scope.get(key), f"target_scope.{key}", errors)
        if isinstance(scope.get("library"), str) and scope["library"] != scope["library"].lower():
            errors.append("target_scope.library: must be lowercase")
        _match(scope.get("surface_ref"), "target_scope.surface_ref", _REF, errors)
        surface_ref = scope.get("surface_ref")

    subjects = _list(value.get("subjects"), "subjects", 1, errors)
    subject_ids: list[str] = []
    subject_map: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(subjects):
        path = f"subjects[{index}]"
        subject = _object(item, path, {"subject_ref", "subject_kind", "surface_ref", "semantic_roles"}, errors)
        if not subject:
            continue
        _match(subject.get("subject_ref"), f"{path}.subject_ref", _REF, errors)
        _enum(subject.get("subject_kind"), f"{path}.subject_kind", _SUBJECT_KINDS, errors)
        _match(subject.get("surface_ref"), f"{path}.surface_ref", _REF, errors)
        semantic_roles = _string_list(subject.get("semantic_roles"), f"{path}.semantic_roles", 1, errors)
        for rindex, role in enumerate(semantic_roles):
            _enum(role, f"{path}.semantic_roles[{rindex}]", OBJECT_ROLES, errors)
        if surface_ref is not None and subject.get("surface_ref") != surface_ref:
            errors.append(f"{path}.surface_ref: outside target semantic surface")
        if isinstance(subject.get("subject_ref"), str):
            subject_ids.append(subject["subject_ref"])
            subject_map[subject["subject_ref"]] = subject
    _duplicates(subject_ids, "subjects", "subject_ref", errors)

    evidence = _list(value.get("evidence"), "evidence", 1, errors)
    evidence_ids: list[str] = []
    evidence_kinds: dict[str, str] = {}
    for index, item in enumerate(evidence):
        path = f"evidence[{index}]"
        record = _object(item, path, {"evidence_id", "kind", "path", "sha256"}, errors)
        if not record:
            continue
        _match(record.get("evidence_id"), f"{path}.evidence_id", _ID, errors)
        _enum(record.get("kind"), f"{path}.kind", _EVIDENCE_KINDS, errors)
        _evidence_path(record, path, root, errors)
        if isinstance(record.get("evidence_id"), str):
            evidence_ids.append(record["evidence_id"])
            if isinstance(record.get("kind"), str):
                evidence_kinds[record["evidence_id"]] = record["kind"]
    _duplicates(evidence_ids, "evidence", "evidence_id", errors)

    facts = _list(value.get("facts"), "facts", 1, errors)
    fact_ids: list[str] = []
    conflict_groups: dict[tuple[str, str, str, str], set[str]] = {}
    for index, item in enumerate(facts):
        path = f"facts[{index}]"
        fact = _object(
            item,
            path,
            {"fact_id", "subject_ref", "coverage", "fact_type", "parameters", "assertion", "epistemic_status", "evidence_refs"},
            errors,
        )
        if not fact:
            continue
        _match(fact.get("fact_id"), f"{path}.fact_id", _ID, errors)
        _match(fact.get("subject_ref"), f"{path}.subject_ref", _REF, errors)
        _enum(fact.get("coverage"), f"{path}.coverage", {item.value for item in FactCoverage}, errors)
        fact_type = fact.get("fact_type")
        if not isinstance(fact_type, str) or fact_type not in FACT_PARAMETER_KEYS:
            errors.append(f"{path}.fact_type: unknown fact type {fact_type!r}")
        else:
            errors.extend(validate_fact_parameters(fact_type, fact.get("parameters"), f"{path}.parameters"))
        _enum(fact.get("assertion"), f"{path}.assertion", {item.value for item in Assertion}, errors)
        _enum(fact.get("epistemic_status"), f"{path}.epistemic_status", {item.value for item in EpistemicStatus}, errors)
        refs = _string_list(fact.get("evidence_refs"), f"{path}.evidence_refs", 1, errors)
        for rindex, ref in enumerate(refs):
            if ref not in set(evidence_ids):
                errors.append(f"{path}.evidence_refs[{rindex}]: dangling evidence reference {ref!r}")
        subject_ref = fact.get("subject_ref")
        if isinstance(subject_ref, str) and subject_ref not in subject_map:
            errors.append(f"{path}.subject_ref: dangling subject reference {subject_ref!r}")
        parameters = fact.get("parameters")
        if isinstance(parameters, dict):
            for pindex, participant in enumerate(parameters.get("participant_refs", [])):
                if participant not in subject_map:
                    errors.append(f"{path}.parameters.participant_refs[{pindex}]: dangling subject reference {participant!r}")
        if fact.get("epistemic_status") == EpistemicStatus.VERIFIED.value:
            referenced_kinds = {evidence_kinds.get(ref) for ref in refs}
            if "llm_proposal" in referenced_kinds:
                errors.append(f"{path}: LLM evidence cannot establish VERIFIED fact")
            if not referenced_kinds.intersection(_DETERMINISTIC_EVIDENCE):
                errors.append(f"{path}: VERIFIED fact requires deterministic evidence")
            if isinstance(fact_type, str) and isinstance(subject_ref, str) and isinstance(parameters, dict):
                semantic_key = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
                key = (fact_type, subject_ref, str(fact.get("coverage")), semantic_key)
                conflict_groups.setdefault(key, set()).add(str(fact.get("assertion")))
        if isinstance(fact.get("fact_id"), str):
            fact_ids.append(fact["fact_id"])
    _duplicates(fact_ids, "facts", "fact_id", errors)
    for key, assertions in sorted(conflict_groups.items()):
        if {Assertion.TRUE.value, Assertion.FALSE.value}.issubset(assertions):
            errors.append(f"facts: conflicting VERIFIED facts for {key[0]} on {key[1]}")
    return sorted(dict.fromkeys(errors))


def validate_profile_or_raise(value: Any, repo_root: str | Path | None = None) -> None:
    errors = validate_profile(value, repo_root=repo_root)
    if errors:
        raise SchemaValidationError("TargetSemanticProfile", errors)


def canonical_profile_bytes(value: Mapping[str, Any], repo_root: str | Path | None = None) -> bytes:
    validate_profile_or_raise(value, repo_root=repo_root)
    return yaml.safe_dump(dict(value), allow_unicode=True, default_flow_style=False, sort_keys=True).encode("utf-8")


def profile_digest(value: Mapping[str, Any], repo_root: str | Path | None = None) -> str:
    return hashlib.sha256(canonical_profile_bytes(value, repo_root=repo_root)).hexdigest()


def _keys(value: Mapping[str, Any], path: str, required: set[str], errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{_path(path, key)}: required field missing")
    for key in sorted(set(value) - required, key=str):
        errors.append(f"{_path(path, str(key))}: unknown field")


def _object(value: Any, path: str, required: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, required, errors)
    return value


def _list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _string_list(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    for index, item in enumerate(items):
        _nonempty_string(item, f"{path}[{index}]", errors)
    return [item for item in items if isinstance(item, str)]


def _nonempty_string(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _enum(value: Any, path: str, allowed: Any, errors: list[str]) -> None:
    if not isinstance(value, str) or value not in set(allowed):
        errors.append(f"{path}: unknown value {value!r}")


def _match(value: Any, path: str, pattern: re.Pattern[str], errors: list[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        errors.append(f"{path}: does not match {pattern.pattern!r}")


def _duplicates(values: list[str], path: str, label: str, errors: list[str]) -> None:
    for value, count in Counter(values).items():
        if count > 1:
            errors.append(f"{path}: duplicate {label} {value!r}")


def _evidence_path(record: Mapping[str, Any], path: str, repo_root: Path, errors: list[str]) -> None:
    raw = record.get("path")
    digest = record.get("sha256")
    _nonempty_string(raw, f"{path}.path", errors)
    _match(digest, f"{path}.sha256", _SHA256, errors)
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
    elif isinstance(digest, str) and _SHA256.fullmatch(digest):
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual != digest:
            errors.append(f"{path}.sha256: digest mismatch")


def _path(parent: str, key: str) -> str:
    return key if parent == "$" else f"{parent}.{key}"
