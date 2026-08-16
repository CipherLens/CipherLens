"""Load, validate, and canonically write CipherLens trace v2 JSONL files."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Mapping

import yaml


_VC_SCHEMA_PATH = Path(__file__).with_name("vc.schema.yaml")
_HEADER_FIELDS = (
    "record_type",
    "format",
    "library",
    "build",
    "library_version",
    "pattern_id",
    "pair_kind",
    "source",
)
_EVENT_FIELDS = (
    "record_type",
    "seq",
    "api",
    "role",
    "state_before",
    "state_after",
    "ret",
    "consumed_len",
    "input_len",
    "out_state",
    "sanitizer_event",
    "error_state",
)
_OUT_STATE_FIELDS = (
    "tag_written",
    "tag_value",
    "parse_result",
    "len_cleared",
    "reused_ptr_valid",
)
_STATE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SANITIZER_PATTERN = re.compile(r"^(asan|signal)_[a-z0-9_]+$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]*$")


@dataclass(frozen=True)
class TraceHeader:
    record_type: str
    format: str
    library: str
    build: str
    library_version: str
    pattern_id: str
    pair_kind: str
    source: str


@dataclass(frozen=True)
class TraceEvent:
    record_type: str
    seq: int
    api: str
    role: str | None
    state_before: str | None
    state_after: str | None
    ret: int | None
    consumed_len: int | None
    input_len: int | None
    out_state: dict[str, Any]
    sanitizer_event: str | None
    error_state: str | None


class TraceValidationError(ValueError):
    """One aggregate error containing every detected trace violation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__(
            "invalid trace:\n" + "\n".join(f"- {error}" for error in self.errors)
        )


def load_trace(path: str | Path) -> tuple[TraceHeader, list[TraceEvent]]:
    """Load a canonical trace and validate all T1-T7 requirements."""

    source = Path(path)
    raw = source.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceValidationError(
            [f"T5 file: invalid UTF-8 at byte {exc.start}"]
        ) from exc

    errors: list[str] = []
    parsed: list[tuple[int, Any]] = []
    # Split only on the canonical record delimiter.  Unicode line-separator
    # characters remain valid JSON string content and CRLF is rejected by T6.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines:
        errors.append("T1 line 1: header record required")
    for line_number, line in enumerate(lines, 1):
        if not line:
            errors.append(f"T6 line {line_number}: blank lines are not canonical")
            continue
        try:
            parsed.append((line_number, json.loads(line)))
        except json.JSONDecodeError as exc:
            errors.append(
                f"T5 line {line_number}: invalid JSON at column {exc.colno}: {exc.msg}"
            )

    header, events = _validate_records(parsed, errors)
    errors = _stable_errors(errors)
    if errors:
        raise TraceValidationError(errors)

    assert header is not None
    canonical = _serialize_trace(header, events)
    # T6: semantic validity is not enough; the source bytes must be canonical.
    if raw != canonical:
        raise TraceValidationError(["T6 file: non-canonical trace encoding"])
    return header, events


def dump_trace(
    header: TraceHeader, events: list[TraceEvent], path: str | Path
) -> None:
    """Validate structured trace data and write the canonical byte encoding."""

    records: list[tuple[int, Any]] = [(1, _header_mapping(header))]
    records.extend(
        (index + 2, _event_mapping(event)) for index, event in enumerate(events)
    )
    errors: list[str] = []
    validated_header, validated_events = _validate_records(records, errors)
    errors = _stable_errors(errors)
    if errors:
        raise TraceValidationError(errors)
    assert validated_header is not None
    Path(path).write_bytes(_serialize_trace(validated_header, validated_events))


def _validate_records(
    records: list[tuple[int, Any]], errors: list[str]
) -> tuple[TraceHeader | None, list[TraceEvent]]:
    roles = _load_role_vocabulary()
    header: TraceHeader | None = None
    events: list[TraceEvent] = []
    event_records = 0

    # T1: exactly one valid header on line 1, then at least one event.
    if not records:
        if not any(error.startswith("T1 line 1:") for error in errors):
            errors.append("T1 line 1: header record required")
        errors.append("T1 file: at least one event record required")
        return None, []

    first_line, first_value = records[0]
    first_type = first_value.get("record_type") if isinstance(first_value, dict) else None
    if first_line != 1 or first_type != "header":
        errors.append("T1 line 1.record_type: expected 'header'")

    for position, (line_number, value) in enumerate(records):
        if not isinstance(value, dict):
            errors.append(
                f"T5 line {line_number}: expected object, got {_type_name(value)}"
            )
            continue
        record_type = value.get("record_type")
        if record_type == "header":
            if position != 0 or line_number != 1:
                errors.append(f"T1 line {line_number}: second header is forbidden")
            candidate = _validate_header(value, line_number, errors)
            if position == 0 and line_number == 1:
                header = candidate
        elif record_type == "event":
            event_records += 1
            candidate = _validate_event(value, line_number, roles, errors)
            if candidate is not None:
                events.append(candidate)
        else:
            errors.append(
                f"T5 line {line_number}.record_type: expected 'header' or 'event'"
            )

    if event_records == 0:
        errors.append("T1 file: at least one event record required")

    # T2: event sequence starts at zero and increases by exactly one.
    expected_seq = 0
    for line_number, value in records:
        if not isinstance(value, dict) or value.get("record_type") != "event":
            continue
        seq = value.get("seq")
        if type(seq) is int:
            if seq != expected_seq:
                errors.append(
                    f"T2 line {line_number}.seq: expected {expected_seq}, got {seq}"
                )
            expected_seq += 1

    return header, events


def _validate_header(
    value: Mapping[str, Any], line_number: int, errors: list[str]
) -> TraceHeader | None:
    path = f"line {line_number}"
    if not _validate_keys(value, _HEADER_FIELDS, path, errors):
        structurally_complete = False
    else:
        structurally_complete = True

    for field in _HEADER_FIELDS:
        if field in value and type(value[field]) is not str:
            errors.append(
                f"T5 {path}.{field}: expected string, got {_type_name(value[field])}"
            )
            structurally_complete = False

    literals = {
        "record_type": {"header"},
        "format": {"cipherlens.trace.v2"},
        "build": {"buggy", "fixed"},
        "pair_kind": {"same_library_fix", "cross_library_reference"},
        "source": {"fixture", "instrumented_run"},
    }
    for field, allowed in literals.items():
        item = value.get(field)
        if type(item) is str and item not in allowed:
            errors.append(
                f"T1 {path}.{field}: expected one of {sorted(allowed)!r}, got {item!r}"
            )
            structurally_complete = False
    library = value.get("library")
    if type(library) is str and library != library.lower():
        errors.append(f"T1 {path}.library: must be lowercase")
        structurally_complete = False

    if not structurally_complete:
        return None
    return TraceHeader(**{field: value[field] for field in _HEADER_FIELDS})


def _validate_event(
    value: Mapping[str, Any],
    line_number: int,
    roles: frozenset[str],
    errors: list[str],
) -> TraceEvent | None:
    path = f"line {line_number}"
    structurally_complete = _validate_keys(value, _EVENT_FIELDS, path, errors)

    if value.get("record_type") != "event":
        errors.append(f"T5 {path}.record_type: expected literal 'event'")
        structurally_complete = False

    seq = value.get("seq")
    if "seq" in value and type(seq) is not int:
        errors.append(
            f"T5 {path}.seq: expected integer, got {_type_name(seq)}"
        )
        structurally_complete = False
    api = value.get("api")
    if "api" in value and type(api) is not str:
        errors.append(f"T5 {path}.api: expected string, got {_type_name(api)}")
        structurally_complete = False

    # T3: role is null or a member of the M0 schema's single vocabulary.
    role = value.get("role")
    if "role" in value and role is not None and type(role) is not str:
        errors.append(f"T3 {path}.role: expected string or null")
        structurally_complete = False
    elif type(role) is str and role not in roles:
        errors.append(f"T3 {path}.role: unknown role {role!r}")
        structurally_complete = False

    for field in ("state_before", "state_after"):
        item = value.get(field)
        if field in value and item is not None:
            if type(item) is not str:
                errors.append(f"T5 {path}.{field}: expected string or null")
                structurally_complete = False
            elif _STATE_PATTERN.fullmatch(item) is None:
                errors.append(f"T5 {path}.{field}: expected UPPER_SNAKE or null")
                structurally_complete = False

    for field in ("ret", "consumed_len", "input_len"):
        item = value.get(field)
        if field in value and item is not None and type(item) is not int:
            errors.append(f"T5 {path}.{field}: expected integer or null")
            structurally_complete = False

    # T4: consumed_len and input_len are symmetrically nullable and bounded.
    consumed = value.get("consumed_len")
    input_len = value.get("input_len")
    if (consumed is None) != (input_len is None):
        errors.append(
            f"T4 {path}: consumed_len and input_len must both be null or both be integers"
        )
        structurally_complete = False
    elif type(consumed) is int and type(input_len) is int:
        if consumed < 0 or consumed > input_len:
            errors.append(
                f"T4 {path}.consumed_len: expected 0 <= consumed_len <= input_len"
            )
            structurally_complete = False

    # T7: out_state is a closed, typed observation registry.
    out_state = value.get("out_state")
    if "out_state" in value and not isinstance(out_state, dict):
        errors.append(
            f"T7 {path}.out_state: expected object, got {_type_name(out_state)}"
        )
        structurally_complete = False
    elif isinstance(out_state, dict):
        if not _validate_out_state(out_state, path, errors):
            structurally_complete = False

    sanitizer = value.get("sanitizer_event")
    if "sanitizer_event" in value and sanitizer is not None:
        if type(sanitizer) is not str:
            errors.append(f"T7 {path}.sanitizer_event: expected string or null")
            structurally_complete = False
        elif _SANITIZER_PATTERN.fullmatch(sanitizer) is None:
            errors.append(
                f"T7 {path}.sanitizer_event: invalid normalized value {sanitizer!r}"
            )
            structurally_complete = False

    error_state = value.get("error_state")
    if "error_state" in value and error_state is not None and type(error_state) is not str:
        errors.append(f"T5 {path}.error_state: expected string or null")
        structurally_complete = False

    if not structurally_complete:
        return None
    return TraceEvent(**{field: value[field] for field in _EVENT_FIELDS})


def _validate_keys(
    value: Mapping[str, Any],
    fields: tuple[str, ...],
    path: str,
    errors: list[str],
) -> bool:
    # T5: required and unknown fields are rejected at every schema depth.
    valid = True
    allowed = set(fields)
    for field in fields:
        if field not in value:
            errors.append(f"T5 {path}.{field}: required field missing")
            valid = False
    for field in sorted(set(value) - allowed, key=str):
        errors.append(f"T5 {path}.{field}: unknown field")
        valid = False
    return valid


def _validate_out_state(
    out_state: Mapping[str, Any], path: str, errors: list[str]
) -> bool:
    valid = True
    for key in sorted(set(out_state) - set(_OUT_STATE_FIELDS), key=str):
        errors.append(f"T7 {path}.out_state.{key}: unknown key")
        valid = False
    for key in ("tag_written", "len_cleared", "reused_ptr_valid"):
        if key in out_state and type(out_state[key]) is not bool:
            errors.append(f"T7 {path}.out_state.{key}: expected boolean")
            valid = False
    if "tag_value" in out_state:
        tag_value = out_state["tag_value"]
        if (
            type(tag_value) is not str
            or len(tag_value) % 2 != 0
            or _HEX_PATTERN.fullmatch(tag_value) is None
        ):
            errors.append(
                f"T7 {path}.out_state.tag_value: expected lowercase even-length hex string"
            )
            valid = False
    if "parse_result" in out_state:
        parse_result = out_state["parse_result"]
        if type(parse_result) is not str or parse_result not in {"success", "reject"}:
            errors.append(
                f"T7 {path}.out_state.parse_result: expected 'success' or 'reject'"
            )
            valid = False
    return valid


def _load_role_vocabulary() -> frozenset[str]:
    try:
        schema = yaml.safe_load(_VC_SCHEMA_PATH.read_text(encoding="utf-8"))
        roles = schema["enums"]["roles"]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise RuntimeError(f"cannot load role vocabulary from vc.schema.yaml: {exc}") from exc
    if not isinstance(roles, list) or not all(type(role) is str for role in roles):
        raise RuntimeError("vc.schema.yaml enums.roles must be a list of strings")
    return frozenset(roles)


def _header_mapping(header: TraceHeader) -> dict[str, Any]:
    return {field: getattr(header, field) for field in _HEADER_FIELDS}


def _event_mapping(event: TraceEvent) -> dict[str, Any]:
    return {field: getattr(event, field) for field in _EVENT_FIELDS}


def _serialize_trace(header: TraceHeader, events: list[TraceEvent]) -> bytes:
    records = [_header_mapping(header)] + [_event_mapping(event) for event in events]
    lines: list[str] = []
    for record in records:
        if record["record_type"] == "event":
            out_state = record["out_state"]
            record["out_state"] = {
                key: out_state[key] for key in _OUT_STATE_FIELDS if key in out_state
            }
        lines.append(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=False,
                separators=(",", ":"),
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _stable_errors(errors: list[str]) -> list[str]:
    return list(dict.fromkeys(errors))
