"""Raw byte artifacts are immutable provenance, never semantic trace values."""

from __future__ import annotations

import json
from typing import Any, Sequence

from execution_model.canonical import raw_digest


def raw_artifact(ref: str, data: bytes, media_type: str = "text/plain") -> dict[str, str]:
    return {"artifact_ref": ref, "artifact_digest": raw_digest(data), "media_type": media_type}


_SANITIZER_MARKERS = (b"AddressSanitizer", b"UndefinedBehaviorSanitizer", b"runtime error:")
_ORACLE_FIELDS = {
    "capture_binding_ref", "status", "value_presence", "value", "sequence_index",
    "channel_active", "phase_reached", "value_artifact_ref", "value_artifact_digest",
}


def sanitizer_evidence(ref: str, data: bytes) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Convert replayed sanitizer bytes to process evidence, never a Verdict."""

    artifact = raw_artifact(ref, data)
    events = []
    if any(marker in data for marker in _SANITIZER_MARKERS):
        events.append({"evidence_id": f"process:sanitizer:{artifact['artifact_digest']}", "evidence_type": "sanitizer_event", "artifact_refs": [ref]})
    return artifact, events


def oracle_event_acquisitions(ref: str, data: bytes, *, allowed_capture_refs: Sequence[str]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Parse strict replay markers into declared acquisition records."""

    artifact = raw_artifact(ref, data)
    allowed = set(allowed_capture_refs)
    acquisitions: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(data.decode("utf-8", errors="strict").splitlines(), 1):
        if not raw_line.startswith("ORACLE_EVENT "):
            continue
        payload = json.loads(raw_line.removeprefix("ORACLE_EVENT "))
        if not isinstance(payload, dict) or set(payload) - _ORACLE_FIELDS:
            raise ValueError(f"ORACLE_EVENT line {line_number}: unknown fields")
        capture_ref = payload.get("capture_binding_ref")
        if capture_ref not in allowed:
            raise ValueError(f"ORACLE_EVENT line {line_number}: undeclared capture")
        acquisitions.append({**payload, "evidence_refs": [ref]})
    return artifact, acquisitions
