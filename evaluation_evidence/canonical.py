"""Canonical serialization, immutable identity, and semantic safety policy."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from copy import deepcopy
from pathlib import PurePosixPath
from typing import Any, Mapping

from evaluation_evidence.model import SCHEMA_VERSIONS


ID_FIELDS = {
    SCHEMA_VERSIONS["ledger"]: "ledger_id",
    SCHEMA_VERSIONS["artifact_record"]: "artifact_record_id",
    SCHEMA_VERSIONS["test_run_record"]: "test_run_id",
    SCHEMA_VERSIONS["experiment_unit"]: "experiment_unit_id",
    SCHEMA_VERSIONS["metric_definition"]: "metric_definition_id",
    SCHEMA_VERSIONS["metric_population_manifest"]: "population_manifest_id",
    SCHEMA_VERSIONS["metric_record"]: "metric_record_id",
    SCHEMA_VERSIONS["claim_record"]: "claim_id",
    SCHEMA_VERSIONS["claim_gate_report"]: "claim_gate_report_id",
    SCHEMA_VERSIONS["finding_ledger"]: "ledger_id",
}
PREFIXES = {
    schema: field.removesuffix("_id").replace("_", "-")
    for schema, field in ID_FIELDS.items()
}
SET_LIST_KEYS = frozenset({
    "allowed_claim_levels", "allowed_origins", "allowed_report_sections",
    "blocking_refs", "caveats", "forbidden_interpretations", "forbidden_wording",
    "reason_codes", "required_actions", "required_artifact_types", "research_question_refs",
    "validation_maturity",
})
FORBIDDEN_KEYS = frozenset({
    "absolute_path", "api_key", "authorization", "credential", "credentials",
    "hostname", "host_environment", "password", "pid", "private_key", "secret",
    "temporary_path", "timestamp", "token", "workspace_path",
})
SECRET_KEY_RE = re.compile(r"(^|_)(api_?key|auth_?token|access_?token|secret|password|credential|private_?key)($|_)")
SECRET_VALUE_RE = re.compile(r"(^--?(api[-_]?key|token|password|secret)$)|(^|\s)(api[-_]?key|access[-_]?token|password|secret)=|\bsk-[A-Za-z0-9_-]{8,}", re.IGNORECASE)


def _normalize(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize(value[key], str(key)) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        items = [_normalize(item) for item in value]
        if parent_key in SET_LIST_KEYS:
            return sorted(items, key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return items
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, float):
        raise ValueError("floating-point values are forbidden in canonical semantic artifacts")
    if value is None or isinstance(value, (bool, int)):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def semantic_safety_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).lower()
            child = f"{path}.{raw_key}"
            if key in FORBIDDEN_KEYS or SECRET_KEY_RE.search(key):
                errors.append(f"{child}: secret or operational field forbidden")
            errors.extend(semantic_safety_errors(item, child))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            errors.extend(semantic_safety_errors(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if value.startswith("/") or (len(value) > 2 and value[1:3] in {":/", ":\\"}):
            errors.append(f"{path}: absolute path forbidden in semantic artifact")
        if SECRET_VALUE_RE.search(value):
            errors.append(f"{path}: secret-like value forbidden")
    elif isinstance(value, float):
        errors.append(f"{path}: floating-point value forbidden")
    return errors


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    errors = semantic_safety_errors(value)
    if errors:
        raise ValueError("; ".join(sorted(dict.fromkeys(errors))))
    normalized = _normalize(dict(value))
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def semantic_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def raw_digest(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("raw digest input must be bytes")
    return hashlib.sha256(data).hexdigest()


def semantic_id(value: Mapping[str, Any]) -> str:
    schema = str(value.get("schema_version") or "")
    field = ID_FIELDS.get(schema)
    if field is None:
        raise ValueError(f"unsupported canonical schema: {schema}")
    body = deepcopy(dict(value))
    body.pop(field, None)
    return f"{PREFIXES[schema]}:{semantic_digest(body)}"


def identify(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    field = ID_FIELDS.get(str(result.get("schema_version") or ""))
    if field is None:
        raise ValueError("unsupported canonical schema")
    result[field] = semantic_id(result)
    return result


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    from evaluation_evidence.registry import validate_document_or_raise

    validate_document_or_raise(value)
    return canonical_json_bytes(value)


def document_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def persist_canonical(store: Any, ref: str, value: Mapping[str, Any]) -> Any:
    """Persist one validated evidence document in an immutable ArtifactStore."""
    from evaluation_evidence.registry import validate_document_or_raise

    return store.put_canonical(
        ref, value, serializer=lambda document: canonical_bytes(document),
        validator=validate_document_or_raise,
    )


def validate_relative_location(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts
