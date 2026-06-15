"""Load and apply generic mutation operators."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml


DEFAULT_REGISTRY = Path("config/mutation_operator_registry.yaml")


def load_yaml(path: Path) -> Any:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_operator_registry(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    return load_yaml(path)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def der_length_delta(data: bytes) -> bytes:
    if len(data) < 4 or data[0] != 0x30:
        return data[:-1] if len(data) > 1 else b"\x30\x82"
    out = bytearray(data)
    if out[1] == 0x82 and len(out) > 3:
        out[3] = (out[3] + 1) & 0xFF
    elif out[1] == 0x81 and len(out) > 2:
        out[2] = (out[2] + 1) & 0xFF
    else:
        out[1] = (out[1] + 1) & 0x7F
    return bytes(out)


def apply_operator(operator_name: str, operator: dict[str, Any], seed_bytes: bytes) -> bytes:
    if "static_bytes_hex" in operator:
        return bytes.fromhex(str(operator["static_bytes_hex"]))
    if operator_name == "near_valid_length_delta":
        return der_length_delta(seed_bytes)
    if "truncate_bytes" in operator:
        n = int(operator.get("truncate_bytes") or 0)
        return seed_bytes[:-n] if n > 0 and len(seed_bytes) > n else seed_bytes
    if "trailing_bytes_hex" in operator:
        return seed_bytes + bytes.fromhex(str(operator["trailing_bytes_hex"]))
    if "trailing_text" in operator:
        return seed_bytes + str(operator["trailing_text"]).encode("utf-8")
    return seed_bytes


def input_meta(path: Path, data: bytes) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": path.as_posix(), "size_bytes": len(data), "sha256": sha256_bytes(data)}
