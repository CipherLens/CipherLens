"""Immutable declared observation-capture regions for template overlays."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "cipherlens.declared_capture_region.v0.1"
OVERLAY_SCHEMA_VERSION = "cipherlens.trigger_template_interface_overlay.v0.1"
CAPTURE_REGION_ID = "region:c1-overlay:oracle-event-capture"
_ROLES = {"operation_outcome", "consumed_length", "input_length"}
_PHASES = {"BEFORE_STEP", "DURING_STEP", "AFTER_STEP", "BETWEEN_STEPS"}
_MULTIPLICITIES = {"ONE", "ZERO_OR_ONE", "ONE_OR_MORE", "ZERO_OR_MORE"}
_SHA = re.compile(r"^[0-9a-f]{64}$")
_REGION_KEYS = {
    "schema_version", "capture_region_id", "template_ref", "template_digest",
    "source_region_ref", "slot_kind", "semantic_roles", "phase",
    "operation_ref", "protected", "multiplicity", "provenance_refs", "digest",
}


def _canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _identified(value: Mapping[str, Any], prefix: str, field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = prefix + ":" + hashlib.sha256(_canonical_json_bytes(result)).hexdigest()
    return result


def capture_region_digest(value: Mapping[str, Any]) -> str:
    semantic = dict(value)
    semantic.pop("digest", None)
    return hashlib.sha256(_canonical_json_bytes(semantic)).hexdigest()


def validate_declared_capture_region(value: Mapping[str, Any]) -> None:
    unknown = sorted(set(value) - _REGION_KEYS)
    missing = sorted(_REGION_KEYS - set(value))
    errors: list[str] = []
    if unknown:
        errors.append("unknown fields: " + ", ".join(unknown))
    if missing:
        errors.append("missing fields: " + ", ".join(missing))
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("wrong DeclaredCaptureRegion schema")
    if not isinstance(value.get("capture_region_id"), str) or not value["capture_region_id"]:
        errors.append("capture_region_id is required")
    for key in ("template_ref", "source_region_ref", "operation_ref"):
        if not isinstance(value.get(key), str) or not value[key]:
            errors.append(f"{key} is required")
    if _SHA.fullmatch(str(value.get("template_digest", ""))) is None:
        errors.append("template_digest must be SHA-256")
    if value.get("slot_kind") != "OBSERVATION_CAPTURE":
        errors.append("slot_kind must be OBSERVATION_CAPTURE")
    roles = value.get("semantic_roles")
    if not isinstance(roles, list) or not roles or len(roles) != len(set(roles)):
        errors.append("semantic_roles must be a non-empty unique list")
    elif not set(roles).issubset(_ROLES):
        errors.append("unsupported semantic role")
    if value.get("phase") not in _PHASES:
        errors.append("unsupported capture phase")
    if value.get("protected") is not False:
        errors.append("declared capture region must be unprotected")
    if value.get("multiplicity") not in _MULTIPLICITIES:
        errors.append("unsupported multiplicity")
    provenance = value.get("provenance_refs")
    if not isinstance(provenance, list) or not provenance:
        errors.append("template parent provenance is required")
    else:
        for index, edge in enumerate(provenance):
            if not isinstance(edge, dict) or set(edge) != {"ref", "digest"}:
                errors.append(f"provenance_refs[{index}] must be a ref/digest edge")
            elif not edge["ref"] or _SHA.fullmatch(str(edge["digest"])) is None:
                errors.append(f"provenance_refs[{index}] is invalid")
    if not errors and value.get("digest") != capture_region_digest(value):
        errors.append("capture region digest mismatch")
    if errors:
        raise ValueError("invalid DeclaredCaptureRegion: " + "; ".join(errors))


def make_declared_capture_region(
    *,
    capture_region_id: str,
    template_ref: str,
    template_digest: str,
    source_region_ref: str,
    semantic_roles: Sequence[str],
    phase: str,
    operation_ref: str,
    multiplicity: str,
    provenance_refs: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    region: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "capture_region_id": capture_region_id,
        "template_ref": template_ref,
        "template_digest": template_digest,
        "source_region_ref": source_region_ref,
        "slot_kind": "OBSERVATION_CAPTURE",
        "semantic_roles": sorted(dict.fromkeys(semantic_roles)),
        "phase": phase,
        "operation_ref": operation_ref,
        "protected": False,
        "multiplicity": multiplicity,
        "provenance_refs": [dict(edge) for edge in provenance_refs],
    }
    region["digest"] = capture_region_digest(region)
    validate_declared_capture_region(region)
    return region


def make_capture_region_overlay(
    *,
    parent_ref: str,
    parent_digest: str,
    template_ref: str,
    template_digest: str,
    capture_regions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not parent_ref or _SHA.fullmatch(parent_digest) is None:
        raise ValueError("template overlay requires a parent ref/digest")
    if not capture_regions:
        raise ValueError("template overlay requires a capture region")
    regions = []
    for value in capture_regions:
        validate_declared_capture_region(value)
        if value["template_ref"] != template_ref or value["template_digest"] != template_digest:
            raise ValueError("capture region template identity mismatch")
        if {"ref": parent_ref, "digest": parent_digest} not in value["provenance_refs"]:
            raise ValueError("capture region does not preserve template parent lineage")
        regions.append(dict(value))
    return _identified(
        {
            "schema_version": OVERLAY_SCHEMA_VERSION,
            "parent_ref": parent_ref,
            "parent_digest": parent_digest,
            "template_ref": template_ref,
            "template_digest": template_digest,
            "capture_regions": sorted(regions, key=lambda item: item["capture_region_id"]),
            "immutable": True,
            "base_manifest_modified": False,
        },
        "template-interface-overlay",
        "overlay_id",
    )
