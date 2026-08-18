"""Canonicalization for immutable Trigger Template Interface manifests."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Mapping

import yaml


def normalize_manifest(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(dict(value))
    for slot in normalized.get("slots", []):
        for key in ("legacy_source_refs", "dependencies"):
            if isinstance(slot.get(key), list):
                slot[key] = sorted(dict.fromkeys(slot[key]))
    normalized["slots"] = sorted(
        normalized.get("slots", []), key=lambda item: item.get("slot_ref", "")
    )
    normalized["source_mapping"] = sorted(
        normalized.get("source_mapping", []),
        key=lambda item: (item.get("slot_ref", ""), item.get("legacy_source_ref", "")),
    )
    provenance = normalized.get("provenance")
    if isinstance(provenance, dict) and isinstance(provenance.get("source_artifact_refs"), list):
        provenance["source_artifact_refs"] = sorted(dict.fromkeys(provenance["source_artifact_refs"]))
    return normalized


def canonical_manifest_bytes(value: Mapping[str, Any]) -> bytes:
    from trigger_template_interface.validate import validate_manifest_or_raise

    normalized = normalize_manifest(value)
    validate_manifest_or_raise(normalized)
    return yaml.safe_dump(
        normalized, allow_unicode=True, default_flow_style=False, sort_keys=True
    ).encode("utf-8")


def manifest_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_manifest_bytes(value)).hexdigest()
