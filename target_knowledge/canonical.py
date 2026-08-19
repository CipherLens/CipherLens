"""Canonical, path-safe identities for target-knowledge documents."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


_FORBIDDEN_KEY_PARTS = ("secret", "token", "password", "private_key")


def semantic_view(value: Any) -> Any:
    """Return data that may affect semantic identity.

    Local telemetry is intentionally excluded: profiles remain portable while a
    caller may keep absolute local paths in process memory if it needs them.
    """
    if isinstance(value, Mapping):
        return {
            str(key): semantic_view(item)
            for key, item in value.items()
            if str(key) not in {"telemetry", "profile_id", "artifact_id", "manifest_id"}
        }
    if isinstance(value, (list, tuple)):
        return [semantic_view(item) for item in value]
    return value


def semantic_safety_errors(value: Any, path: str = "$") -> list[str]:
    """Reject secrets and absolute paths in semantic documents."""
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            child = f"{path}.{key}"
            if any(part in key_text for part in _FORBIDDEN_KEY_PARTS):
                errors.append(f"forbidden semantic key: {child}")
            if str(key) == "telemetry":
                errors.extend(_telemetry_secret_errors(item, child))
            else:
                errors.extend(semantic_safety_errors(item, child))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            errors.extend(semantic_safety_errors(item, f"{path}[{index}]") )
    elif isinstance(value, str) and value.startswith("/"):
        errors.append(f"absolute path in semantic data: {path}")
    return errors


def _telemetry_secret_errors(value: Any, path: str) -> list[str]:
    """Telemetry may retain local paths, but must never retain credentials."""
    if isinstance(value, Mapping):
        errors = []
        for key, item in value.items():
            child = f"{path}.{key}"
            if any(part in str(key).lower() for part in _FORBIDDEN_KEY_PARTS):
                errors.append(f"forbidden telemetry key: {child}")
            errors.extend(_telemetry_secret_errors(item, child))
        return errors
    if isinstance(value, (list, tuple)):
        return [error for index, item in enumerate(value) for error in _telemetry_secret_errors(item, f"{path}[{index}]")]
    return []


def canonical_json_bytes(value: Any) -> bytes:
    errors = semantic_safety_errors(value)
    if errors:
        raise ValueError("; ".join(errors))
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(semantic_view(value))).hexdigest()


def identified(value: Mapping[str, Any], prefix: str, field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = f"{prefix}:{semantic_digest(result)}"
    return result
