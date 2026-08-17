"""Strict validation and canonical serialization for TS artifacts."""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

import yaml

from transfer_signature.model import (
    ConstraintClass,
    ConstraintResult,
    EVALUATION_SCHEMA_VERSION,
    Eligibility,
    SchemaValidationError,
    TS_SCHEMA_VERSION,
)
from transfer_signature.registry import CONSTRAINT_REGISTRY, validate_constraint_parameters


_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_CONTRACT_REF = re.compile(r"^contract:[A-Z][A-Z0-9_]{2,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTRACT_FAMILIES = frozenset(
    {
        "input_consumption",
        "failure_output_integrity",
        "object_state_consistency",
        "lifecycle_state",
        "wrapper_error_propagation",
        "resource_memory",
    }
)
_DERIVATION_METHODS = frozenset(
    {"direct_projection", "family_rule", "structured_metadata", "reviewed_proposal"}
)
_EVIDENCE_KINDS = frozenset(
    {
        "patch",
        "diff",
        "poc",
        "root_cause",
        "metadata",
        "regression_test",
        "buggy_run",
        "fixed_run",
        "minimal_witness",
        "advisory",
    }
)
_FORBIDDEN_FIELDS = frozenset(
    {
        "target_api",
        "candidatebinding",
        "candidate_binding",
        "candidate_ref",
        "score",
        "verdict",
        "target_result",
        "expected_relation",
    }
)
_CONSTRAINT_REASON_CODES = frozenset(
    {
        "VERIFIED_COMPATIBLE_TRUE",
        "VERIFIED_COMPATIBLE_FALSE",
        "VERIFIED_EXCLUSION_PRESENT",
        "VERIFIED_EXCLUSION_ABSENT",
        "VERIFIED_CHANNEL_AVAILABLE",
        "VERIFIED_CHANNEL_UNAVAILABLE",
        "UNVERIFIED_COMPATIBLE_FACT",
        "NONDETERMINATE_COMPATIBLE_FACT",
        "NO_COMPATIBLE_FACT",
    }
)
_MISSING_REQUIREMENTS = frozenset(
    {
        "COMPATIBLE_FACT",
        "VERIFIED_FACT",
        "SURFACE_NEGATIVE_FACT",
        "COMPATIBLE_SUBJECT",
    }
)
_TOP_REASON_CODES = frozenset(
    {
        "REQUIRED_CAPABILITY_MISMATCH",
        "REQUIRED_OBSERVABILITY_MISMATCH",
        "EXCLUDED_SEMANTIC_MATCH",
        "ALL_ELIGIBILITY_CONDITIONS_MET",
        "UNRESOLVED_CONSTRAINTS",
    }
)


def validate_signature(value: Any, repo_root: str | Path | None = None) -> list[str]:
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    required = {
        "schema_version",
        "signature_id",
        "source_contract_ref",
        "source_contract_digest",
        "source_validation_refs",
        "contract_family",
        "required_capabilities",
        "excluded_semantics",
        "required_observability",
        "provenance",
    }
    _keys(value, "$", required, set(), errors)
    _literal(value.get("schema_version"), "schema_version", TS_SCHEMA_VERSION, errors)
    _match(value.get("signature_id"), "signature_id", _ID, errors)
    _match(value.get("source_contract_ref"), "source_contract_ref", _CONTRACT_REF, errors)
    _match(value.get("source_contract_digest"), "source_contract_digest", _SHA256, errors)
    _enum(value.get("contract_family"), "contract_family", _CONTRACT_FAMILIES, errors)
    _forbidden_fields(value, "$", errors)

    validation_refs = _list(value.get("source_validation_refs"), "source_validation_refs", 1, errors)
    validation_ids: list[str] = []
    for index, item in enumerate(validation_refs):
        path = f"source_validation_refs[{index}]"
        ref = _object(item, path, {"validation_id", "validation_digest"}, set(), errors)
        if ref:
            _match(ref.get("validation_id"), f"{path}.validation_id", _ID, errors)
            _match(ref.get("validation_digest"), f"{path}.validation_digest", _SHA256, errors)
            if isinstance(ref.get("validation_id"), str):
                validation_ids.append(ref["validation_id"])
    _duplicates(validation_ids, "source_validation_refs", "validation_id", errors)

    constraint_groups = (
        ("required_capabilities", ConstraintClass.REQUIRED_CAPABILITY, 1),
        ("excluded_semantics", ConstraintClass.EXCLUDED_SEMANTIC, 0),
        ("required_observability", ConstraintClass.REQUIRED_OBSERVABILITY, 1),
    )
    constraint_ids: list[str] = []
    constraints: list[Mapping[str, Any]] = []
    for key, expected_class, minimum in constraint_groups:
        items = _list(value.get(key), key, minimum, errors)
        for index, item in enumerate(items):
            path = f"{key}[{index}]"
            constraint = _object(
                item,
                path,
                {"constraint_id", "type", "parameters", "derivation_refs"},
                set(),
                errors,
            )
            if not constraint:
                continue
            constraints.append(constraint)
            _match(constraint.get("constraint_id"), f"{path}.constraint_id", _ID, errors)
            constraint_type = constraint.get("type")
            if not isinstance(constraint_type, str) or constraint_type not in CONSTRAINT_REGISTRY:
                errors.append(f"{path}.type: unknown constraint type {constraint_type!r}")
            elif CONSTRAINT_REGISTRY[constraint_type].constraint_class is not expected_class:
                errors.append(f"{path}.type: not valid for {key}")
            else:
                errors.extend(
                    validate_constraint_parameters(
                        constraint_type, constraint.get("parameters"), f"{path}.parameters"
                    )
                )
            derivation_refs = _string_list(
                constraint.get("derivation_refs"), f"{path}.derivation_refs", 1, errors
            )
            for dindex, ref in enumerate(derivation_refs):
                _match(ref, f"{path}.derivation_refs[{dindex}]", _ID, errors)
            if isinstance(constraint.get("constraint_id"), str):
                constraint_ids.append(constraint["constraint_id"])
    _duplicates(constraint_ids, "constraints", "constraint_id", errors)

    provenance = _object(
        value.get("provenance"),
        "provenance",
        {"producer", "evidence", "derivations"},
        set(),
        errors,
    )
    evidence_ids: list[str] = []
    derivation_ids: list[str] = []
    derivation_constraints: list[str] = []
    if provenance:
        producer = _object(
            provenance.get("producer"),
            "provenance.producer",
            {"name", "version", "mode"},
            set(),
            errors,
        )
        if producer:
            for key in ("name", "version"):
                _nonempty_string(producer.get(key), f"provenance.producer.{key}", errors)
            _literal(
                producer.get("mode"),
                "provenance.producer.mode",
                "deterministic_family_rule",
                errors,
            )
        evidence = _list(provenance.get("evidence"), "provenance.evidence", 1, errors)
        for index, item in enumerate(evidence):
            path = f"provenance.evidence[{index}]"
            record = _object(item, path, {"evidence_id", "kind", "path", "sha256"}, set(), errors)
            if not record:
                continue
            _match(record.get("evidence_id"), f"{path}.evidence_id", _ID, errors)
            _enum(record.get("kind"), f"{path}.kind", _EVIDENCE_KINDS, errors)
            _evidence_path(record, path, root, errors)
            if isinstance(record.get("evidence_id"), str):
                evidence_ids.append(record["evidence_id"])
        _duplicates(evidence_ids, "provenance.evidence", "evidence_id", errors)

        derivations = _list(
            provenance.get("derivations"), "provenance.derivations", 1, errors
        )
        for index, item in enumerate(derivations):
            path = f"provenance.derivations[{index}]"
            derivation = _object(
                item,
                path,
                {"derivation_id", "constraint_ref", "method", "rule_id", "source_refs"},
                set(),
                errors,
            )
            if not derivation:
                continue
            _match(derivation.get("derivation_id"), f"{path}.derivation_id", _ID, errors)
            _match(derivation.get("constraint_ref"), f"{path}.constraint_ref", _ID, errors)
            _enum(derivation.get("method"), f"{path}.method", _DERIVATION_METHODS, errors)
            _nonempty_string(derivation.get("rule_id"), f"{path}.rule_id", errors)
            sources = _string_list(derivation.get("source_refs"), f"{path}.source_refs", 1, errors)
            for sindex, source in enumerate(sources):
                if not source.startswith(("contract:/", "evidence:", "family_rule:", "source_patch:")):
                    errors.append(f"{path}.source_refs[{sindex}]: unsupported provenance reference")
                if source.startswith("evidence:") and source.split(":", 1)[1] not in set(evidence_ids):
                    errors.append(f"{path}.source_refs[{sindex}]: dangling evidence reference")
            if isinstance(derivation.get("derivation_id"), str):
                derivation_ids.append(derivation["derivation_id"])
            if isinstance(derivation.get("constraint_ref"), str):
                derivation_constraints.append(derivation["constraint_ref"])
        _duplicates(derivation_ids, "provenance.derivations", "derivation_id", errors)

    declared_constraints = set(constraint_ids)
    declared_derivations = set(derivation_ids)
    for index, constraint in enumerate(constraints):
        for ref in constraint.get("derivation_refs", []):
            if ref not in declared_derivations:
                errors.append(f"constraints[{index}].derivation_refs: dangling reference {ref!r}")
    for index, constraint_ref in enumerate(derivation_constraints):
        if constraint_ref not in declared_constraints:
            errors.append(
                f"provenance.derivations[{index}].constraint_ref: dangling reference {constraint_ref!r}"
            )
    for constraint_id in sorted(declared_constraints - set(derivation_constraints)):
        errors.append(f"constraint {constraint_id!r}: missing field-level derivation")
    return sorted(dict.fromkeys(errors))


def validate_signature_or_raise(
    value: Any, repo_root: str | Path | None = None
) -> None:
    errors = validate_signature(value, repo_root=repo_root)
    if errors:
        raise SchemaValidationError("Transfer Signature", errors)


def canonical_signature_bytes(
    value: Mapping[str, Any], repo_root: str | Path | None = None
) -> bytes:
    validate_signature_or_raise(value, repo_root=repo_root)
    return _canonical_bytes(value)


def signature_digest(
    value: Mapping[str, Any], repo_root: str | Path | None = None
) -> str:
    return hashlib.sha256(canonical_signature_bytes(value, repo_root=repo_root)).hexdigest()


def validate_evaluation(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    required = {
        "schema_version",
        "signature_id",
        "profile_id",
        "constraint_results",
        "eligibility",
        "reason_codes",
    }
    _keys(value, "$", required, set(), errors)
    _literal(value.get("schema_version"), "schema_version", EVALUATION_SCHEMA_VERSION, errors)
    _match(value.get("signature_id"), "signature_id", _ID, errors)
    _match(value.get("profile_id"), "profile_id", _ID, errors)
    _enum(value.get("eligibility"), "eligibility", {item.value for item in Eligibility}, errors)
    reason_codes = _string_list(value.get("reason_codes"), "reason_codes", 1, errors)
    for index, code in enumerate(reason_codes):
        _enum(code, f"reason_codes[{index}]", _TOP_REASON_CODES, errors)
    results = _list(value.get("constraint_results"), "constraint_results", 1, errors)
    result_ids: list[str] = []
    for index, item in enumerate(results):
        path = f"constraint_results[{index}]"
        result = _object(
            item,
            path,
            {
                "constraint_id",
                "constraint_class",
                "result",
                "matched_fact_refs",
                "reason_code",
                "missing_fact_requirements",
            },
            set(),
            errors,
        )
        if not result:
            continue
        _match(result.get("constraint_id"), f"{path}.constraint_id", _ID, errors)
        _enum(
            result.get("constraint_class"),
            f"{path}.constraint_class",
            {item.value for item in ConstraintClass},
            errors,
        )
        _enum(
            result.get("result"),
            f"{path}.result",
            {item.value for item in ConstraintResult},
            errors,
        )
        _enum(result.get("reason_code"), f"{path}.reason_code", _CONSTRAINT_REASON_CODES, errors)
        _string_list(result.get("matched_fact_refs"), f"{path}.matched_fact_refs", 0, errors)
        missing = _string_list(
            result.get("missing_fact_requirements"),
            f"{path}.missing_fact_requirements",
            0,
            errors,
        )
        for mindex, requirement in enumerate(missing):
            _enum(requirement, f"{path}.missing_fact_requirements[{mindex}]", _MISSING_REQUIREMENTS, errors)
        if isinstance(result.get("constraint_id"), str):
            result_ids.append(result["constraint_id"])
    _duplicates(result_ids, "constraint_results", "constraint_id", errors)
    return sorted(dict.fromkeys(errors))


def validate_evaluation_or_raise(value: Any) -> None:
    errors = validate_evaluation(value)
    if errors:
        raise SchemaValidationError("TS evaluation", errors)


def canonical_evaluation_bytes(value: Mapping[str, Any]) -> bytes:
    validate_evaluation_or_raise(value)
    return _canonical_bytes(value)


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return yaml.safe_dump(
        dict(value), allow_unicode=True, default_flow_style=False, sort_keys=True
    ).encode("utf-8")


def _keys(value: Mapping[str, Any], path: str, required: set[str], optional: set[str], errors: list[str]) -> None:
    for key in sorted(required - set(value)):
        errors.append(f"{_path(path, key)}: required field missing")
    for key in sorted(set(value) - required - optional, key=str):
        errors.append(f"{_path(path, str(key))}: unknown field")


def _object(value: Any, path: str, required: set[str], optional: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, required, optional, errors)
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


def _literal(value: Any, path: str, expected: str, errors: list[str]) -> None:
    if value != expected:
        errors.append(f"{path}: expected literal {expected!r}, got {value!r}")


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


def _forbidden_fields(value: Any, path: str, errors: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _FORBIDDEN_FIELDS:
                errors.append(f"{_path(path, str(key))}: forbidden TS field")
            _forbidden_fields(child, _path(path, str(key)), errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _forbidden_fields(child, f"{path}[{index}]", errors)


def _path(parent: str, key: str) -> str:
    return key if parent == "$" else f"{parent}.{key}"
