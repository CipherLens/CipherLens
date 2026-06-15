"""Parser helpers for ORACLE_EVENT key=value lines."""

from __future__ import annotations

import shlex
from typing import Any


PREFIX = "ORACLE_EVENT"


def _coerce(value: str) -> Any:
    lower = value.lower()
    if lower in {"true", "false"}:
        return lower == "true"
    if lower in {"unknown", "none", "null"}:
        return value
    try:
        return int(value)
    except ValueError:
        return value


def parse_oracle_event_line(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text.startswith(PREFIX):
        return None
    rest = text[len(PREFIX) :].strip()
    if not rest:
        return {}
    event: dict[str, Any] = {}
    for token in shlex.split(rest):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            event[key] = _coerce(value)
    return event


def parse_oracle_events(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        event = parse_oracle_event_line(line)
        if event is not None:
            events.append(event)
    return events
