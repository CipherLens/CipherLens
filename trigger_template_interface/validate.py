"""Closed recursive validation for Trigger Template Interface manifests."""

from __future__ import annotations

from collections import Counter
import hashlib
import re
from typing import Any, Mapping

from trigger_template_interface.model import (
    INTERFACE_VERSION,
    SCHEMA_VERSION,
    ManifestError,
    Multiplicity,
    SlotKind,
)


_SHA = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{1,255}$")
_TOP = {"schema_version", "manifest_id", "trigger_template_ref", "trigger_template_digest", "interface_version", "slots", "source_mapping", "provenance"}
_SLOT = {"slot_ref", "slot_kind", "required", "multiplicity", "source_locator", "legacy_source_refs", "semantic_role_hint", "dependencies", "provenance"}
_LOCATOR = {"artifact_ref", "selector_kind", "selector_value", "line_start", "line_end"}
_SLOT_PROVENANCE = {"source_kind", "source_digest"}
_MAPPING = {"slot_ref", "legacy_source_ref"}
_PROVENANCE = {"producer", "adapter_version", "source_artifact_refs"}


def validate_manifest(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["$: expected object"]
    _keys(value, "$", _TOP, errors)
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version: expected {SCHEMA_VERSION!r}")
    if value.get("interface_version") != INTERFACE_VERSION:
        errors.append(f"interface_version: expected {INTERFACE_VERSION!r}")
    _ref(value.get("manifest_id"), "manifest_id", errors)
    _ref(value.get("trigger_template_ref"), "trigger_template_ref", errors)
    _sha(value.get("trigger_template_digest"), "trigger_template_digest", errors)

    slots = _list(value.get("slots"), "slots", 1, errors)
    slot_refs: list[str] = []
    legacy_to_slots: dict[str, set[str]] = {}
    for index, slot in enumerate(slots):
        path = f"slots[{index}]"
        if not isinstance(slot, dict):
            errors.append(f"{path}: expected object")
            continue
        _keys(slot, path, _SLOT, errors)
        _ref(slot.get("slot_ref"), f"{path}.slot_ref", errors)
        _enum(slot.get("slot_kind"), f"{path}.slot_kind", {x.value for x in SlotKind}, errors)
        if not isinstance(slot.get("required"), bool):
            errors.append(f"{path}.required: expected boolean")
        _enum(slot.get("multiplicity"), f"{path}.multiplicity", {x.value for x in Multiplicity}, errors)
        if slot.get("required") is True and slot.get("multiplicity") in {"ZERO_OR_ONE", "ZERO_OR_MORE"}:
            errors.append(f"{path}.multiplicity: required slot cannot have zero minimum")
        locator = _object(slot.get("source_locator"), f"{path}.source_locator", _LOCATOR, errors)
        if locator:
            for key in ("artifact_ref", "selector_kind", "selector_value"):
                _text(locator.get(key), f"{path}.source_locator.{key}", errors)
            for key in ("line_start", "line_end"):
                if locator.get(key) is not None and (not isinstance(locator[key], int) or locator[key] < 1):
                    errors.append(f"{path}.source_locator.{key}: expected positive integer or null")
        legacy = _strings(slot.get("legacy_source_refs"), f"{path}.legacy_source_refs", 1, errors)
        _text(slot.get("semantic_role_hint"), f"{path}.semantic_role_hint", errors)
        dependencies = _strings(slot.get("dependencies"), f"{path}.dependencies", 0, errors)
        provenance = _object(slot.get("provenance"), f"{path}.provenance", _SLOT_PROVENANCE, errors)
        if provenance:
            _text(provenance.get("source_kind"), f"{path}.provenance.source_kind", errors)
            _sha(provenance.get("source_digest"), f"{path}.provenance.source_digest", errors)
        ref = slot.get("slot_ref")
        if isinstance(ref, str):
            slot_refs.append(ref)
            for legacy_ref in legacy:
                legacy_to_slots.setdefault(legacy_ref, set()).add(ref)
            if ref in dependencies:
                errors.append(f"{path}.dependencies: self dependency")
    _duplicates(slot_refs, "slots", "slot_ref", errors)
    known = set(slot_refs)
    for index, slot in enumerate(slots):
        if isinstance(slot, dict):
            for dependency in slot.get("dependencies", []):
                if dependency not in known:
                    errors.append(f"slots[{index}].dependencies: dangling slot {dependency!r}")
    for legacy, refs in sorted(legacy_to_slots.items()):
        if len(refs) > 1:
            errors.append(f"slots: ambiguous legacy mapping {legacy!r}")

    mappings = _list(value.get("source_mapping"), "source_mapping", 1, errors)
    seen_pairs: list[str] = []
    mapped_pairs: set[tuple[str, str]] = set()
    for index, mapping in enumerate(mappings):
        path = f"source_mapping[{index}]"
        item = _object(mapping, path, _MAPPING, errors)
        if not item:
            continue
        _ref(item.get("slot_ref"), f"{path}.slot_ref", errors)
        _text(item.get("legacy_source_ref"), f"{path}.legacy_source_ref", errors)
        pair = (item.get("slot_ref"), item.get("legacy_source_ref"))
        if all(isinstance(x, str) for x in pair):
            mapped_pairs.add(pair)  # type: ignore[arg-type]
            seen_pairs.append("\0".join(pair))  # type: ignore[arg-type]
        if item.get("slot_ref") not in known:
            errors.append(f"{path}.slot_ref: dangling slot reference")
    _duplicates(seen_pairs, "source_mapping", "mapping", errors)
    expected_pairs = {(slot["slot_ref"], legacy) for slot in slots if isinstance(slot, dict) and isinstance(slot.get("slot_ref"), str) for legacy in slot.get("legacy_source_refs", []) if isinstance(legacy, str)}
    if mapped_pairs != expected_pairs:
        errors.append("source_mapping: must exactly cover slot legacy_source_refs")

    provenance = _object(value.get("provenance"), "provenance", _PROVENANCE, errors)
    if provenance:
        _text(provenance.get("producer"), "provenance.producer", errors)
        _text(provenance.get("adapter_version"), "provenance.adapter_version", errors)
        _strings(provenance.get("source_artifact_refs"), "provenance.source_artifact_refs", 1, errors)
    return sorted(dict.fromkeys(errors))


def validate_manifest_or_raise(value: Any) -> None:
    errors = validate_manifest(value)
    if errors:
        raise ManifestError(errors)


def _keys(value: Mapping[str, Any], path: str, expected: set[str], errors: list[str]) -> None:
    for key in sorted(expected - set(value)):
        errors.append(f"{path}.{key}: required field missing")
    for key in sorted(set(value) - expected, key=str):
        errors.append(f"{path}.{key}: unknown field")


def _object(value: Any, path: str, keys: set[str], errors: list[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(f"{path}: expected object")
        return None
    _keys(value, path, keys, errors)
    return value


def _list(value: Any, path: str, minimum: int, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{path}: expected list")
        return []
    if len(value) < minimum:
        errors.append(f"{path}: expected at least {minimum} item(s)")
    return value


def _strings(value: Any, path: str, minimum: int, errors: list[str]) -> list[str]:
    items = _list(value, path, minimum, errors)
    for index, item in enumerate(items):
        _text(item, f"{path}[{index}]", errors)
    return [item for item in items if isinstance(item, str) and item]


def _text(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or not value:
        errors.append(f"{path}: expected non-empty string")


def _ref(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        errors.append(f"{path}: invalid reference")


def _sha(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        errors.append(f"{path}: expected lowercase SHA-256")


def _enum(value: Any, path: str, allowed: set[str], errors: list[str]) -> None:
    if value not in allowed:
        errors.append(f"{path}: unknown value {value!r}")


def _duplicates(values: list[str], path: str, label: str, errors: list[str]) -> None:
    for value, count in Counter(values).items():
        if count > 1:
            errors.append(f"{path}: duplicate {label} {value!r}")
