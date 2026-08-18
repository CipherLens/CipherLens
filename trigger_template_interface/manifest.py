"""Read-only adapters from legacy normalized templates to stable slot manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

import yaml

from trigger_template_interface.canonical import canonical_manifest_bytes
from trigger_template_interface.model import INTERFACE_VERSION, SCHEMA_VERSION, ManifestError, Multiplicity, SlotKind
from trigger_template_interface.registry import infer_slot_kind


def build_manifest(
    *,
    trigger_template_ref: str,
    trigger_template_digest: str,
    units: Iterable[Mapping[str, Any]],
    source_artifact_ref: str,
) -> dict[str, Any]:
    """Build an immutable manifest without changing the source template."""

    slots_by_ref: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for unit in units:
        kind = infer_slot_kind(dict(unit))
        if kind is None:
            continue
        legacy_ref = unit.get("unit_id") or unit.get("name")
        role = unit.get("role")
        semantic_anchor = _semantic_anchor(unit, kind)
        if not isinstance(legacy_ref, str) or not legacy_ref or semantic_anchor is None:
            missing.append(str(legacy_ref or unit.get("code") or "<unknown>"))
            continue
        slot_ref = _slot_ref(trigger_template_ref, kind, semantic_anchor)
        line_start = unit.get("line_start", unit.get("line"))
        line_end = unit.get("line_end", unit.get("line"))
        source_digest = hashlib.sha256(
            json.dumps(dict(unit), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        slot = {
            "slot_ref": slot_ref,
            "slot_kind": kind.value,
            "required": role in {"trigger_call", "oracle", "mutation_point"},
            "multiplicity": (
                Multiplicity.ONE_OR_MORE.value
                if kind in {SlotKind.INPUT, SlotKind.OBSERVATION}
                else Multiplicity.ONE.value
            ),
            "source_locator": {
                "artifact_ref": source_artifact_ref,
                "selector_kind": "legacy_identity",
                "selector_value": legacy_ref,
                "line_start": line_start if isinstance(line_start, int) else None,
                "line_end": line_end if isinstance(line_end, int) else None,
            },
            "legacy_source_refs": [legacy_ref],
            "semantic_role_hint": str(role),
            "dependencies": [],
            "provenance": {"source_kind": "legacy_selected_unit", "source_digest": source_digest},
        }
        existing = slots_by_ref.get(slot_ref)
        if existing is None:
            slots_by_ref[slot_ref] = slot
        else:
            existing["legacy_source_refs"] = sorted(
                {*existing["legacy_source_refs"], legacy_ref}
            )
    if missing:
        raise ManifestError([f"missing identity evidence for legacy unit {item!r}" for item in missing])
    slots = list(slots_by_ref.values())
    if not slots:
        raise ManifestError(["adapter produced no interface slots"])
    source_mapping = [
        {"slot_ref": slot["slot_ref"], "legacy_source_ref": legacy}
        for slot in slots for legacy in slot["legacy_source_refs"]
    ]
    basis = {
        "trigger_template_ref": trigger_template_ref,
        "trigger_template_digest": trigger_template_digest,
        "slot_refs": sorted(slot["slot_ref"] for slot in slots),
    }
    manifest_id = "manifest:" + hashlib.sha256(
        json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": manifest_id,
        "trigger_template_ref": trigger_template_ref,
        "trigger_template_digest": trigger_template_digest,
        "interface_version": INTERFACE_VERSION,
        "slots": slots,
        "source_mapping": source_mapping,
        "provenance": {
            "producer": "trigger_template_interface.manifest",
            "adapter_version": INTERFACE_VERSION,
            "source_artifact_refs": [source_artifact_ref],
        },
    }
    canonical_manifest_bytes(manifest)
    return manifest


def adapt_normalized_template(template_directory: str | Path, *, repo_root: str | Path) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    directory = Path(template_directory).resolve()
    try:
        relative = directory.relative_to(root).as_posix()
    except ValueError as exc:
        raise ManifestError(["template directory must be inside repository root"]) from exc
    meta_path = directory / "template_meta.yaml"
    units_path = directory / "selected_mask_units.yaml"
    if not meta_path.is_file() or not units_path.is_file():
        raise ManifestError(["template_meta.yaml and selected_mask_units.yaml are required"])
    meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
    selected = yaml.safe_load(units_path.read_text(encoding="utf-8"))
    if not isinstance(meta, dict) or not isinstance(selected, dict) or not isinstance(selected.get("selected_units"), list):
        raise ManifestError(["legacy template metadata has invalid structure"])
    template_id = meta.get("template_id")
    if not isinstance(template_id, str) or not template_id:
        raise ManifestError(["template_meta.template_id is required"])
    digest = _template_digest(directory)
    return build_manifest(
        trigger_template_ref=f"template:{template_id}",
        trigger_template_digest=digest,
        units=selected["selected_units"],
        source_artifact_ref=f"{relative}/selected_mask_units.yaml",
    )


def _semantic_anchor(unit: Mapping[str, Any], kind: SlotKind) -> str | None:
    identity = unit.get("placeholder") or unit.get("mutation_name") or unit.get("name") or unit.get("function")
    code = unit.get("code")
    if not isinstance(identity, str) or not identity.strip():
        if not isinstance(code, str) or not code.strip():
            return None
        identity = re.sub(r"\s+", " ", code.strip())
    role = str(unit.get("role") or "")
    return f"{kind.value}|{role}|{identity.strip()}"


def _slot_ref(template_ref: str, kind: SlotKind, anchor: str) -> str:
    digest = hashlib.sha256(f"{template_ref}\0{anchor}".encode("utf-8")).hexdigest()[:20]
    return f"slot:{kind.value.lower()}:{digest}"


def _template_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for name in ("template_meta.yaml", "selected_mask_units.yaml", "tmpl_mbedtls.c"):
        path = directory / name
        if path.is_file():
            digest.update(name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()
