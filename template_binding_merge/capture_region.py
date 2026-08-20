"""Fail-closed Merge and SourceMap extensions for declared capture regions."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from trigger_template_interface.capture_region import validate_declared_capture_region

from .canonical import merge_digest, semantic_digest, source_map_digest


_ROLE_BY_OBSERVABLE = {
    "PARSE_OUTCOME": "operation_outcome",
    "CONSUMED_LENGTH": "consumed_length",
    "INPUT_LENGTH": "input_length",
}
_SHA = re.compile(r"^[0-9a-f]{64}$")


def _identified(value: Mapping[str, Any], prefix: str, field: str) -> dict[str, Any]:
    result = dict(value)
    result[field] = prefix + ":" + semantic_digest(result)
    return result


def make_merge_capture_binding(
    merge: Mapping[str, Any],
    region: Mapping[str, Any],
    *,
    emitter_ref: str,
    emitter_digest: str,
) -> dict[str, Any]:
    validate_declared_capture_region(region)
    if region.get("template_ref") != merge.get("trigger_template_ref") or region.get("template_digest") != merge.get("trigger_template_digest"):
        raise ValueError("capture region Trigger Template identity mismatch")
    if not emitter_ref or _SHA.fullmatch(emitter_digest) is None:
        raise ValueError("RuntimeEvent emitter ref/digest is required")
    bindings: list[dict[str, Any]] = []
    for capture in merge.get("observation_capture_bindings", []):
        role = _ROLE_BY_OBSERVABLE.get(capture.get("contract_observable_ref"))
        if role is None:
            continue
        if role not in region["semantic_roles"]:
            raise ValueError(f"capture region does not declare role {role}")
        if capture.get("phase") != region["phase"]:
            raise ValueError("capture phase does not match declared region")
        if capture.get("target_operation_binding_ref") != region["operation_ref"]:
            raise ValueError("capture operation does not match declared region")
        bindings.append({
            "capture_binding_id": capture["capture_binding_id"],
            "observation_binding_ref": capture["observation_binding_ref"],
            "capture_region_ref": region["capture_region_id"],
            "capture_region_digest": region["digest"],
            "runtime_event_emitter_ref": emitter_ref,
            "runtime_event_emitter_digest": emitter_digest,
            "semantic_role": role,
            "acquisition_kind": capture["acquisition_kind"],
            "phase": capture["phase"],
            "operation_ref": capture["target_operation_binding_ref"],
            "template_observation_slot_ref": capture["template_observation_slot_ref"],
            "semantic_source_ref": capture["semantic_source_ref"],
        })
    if set(item["semantic_role"] for item in bindings) != set(region["semantic_roles"]):
        raise ValueError("Merge captures do not exactly cover declared semantic roles")
    return _identified(
        {
            "schema_version": "cipherlens.merge_capture_region_binding.v0.1",
            "merge_ref": merge["merge_id"],
            "merge_digest": merge_digest(merge),
            "capture_region_ref": region["capture_region_id"],
            "capture_region_digest": region["digest"],
            "runtime_event_emitter": {"ref": emitter_ref, "digest": emitter_digest},
            "bindings": sorted(bindings, key=lambda item: item["semantic_role"]),
            "candidate_binding_semantics_modified": False,
            "observation_sources_modified": False,
            "api_selection_modified": False,
        },
        "merge-capture-region-binding",
        "binding_manifest_id",
    )


def make_source_map_capture_extension(
    source_map: Mapping[str, Any],
    merge: Mapping[str, Any],
    overlay: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    current_merge_digest = merge_digest(merge)
    current_source_map_digest = source_map_digest(source_map)
    if source_map.get("merge_ref") != merge.get("merge_id"):
        raise ValueError("SourceMap Merge ref mismatch")
    if source_map.get("merge_digest") != current_merge_digest:
        raise ValueError("SourceMap Merge digest mismatch")
    if binding.get("merge_ref") != merge.get("merge_id") or binding.get("merge_digest") != current_merge_digest:
        raise ValueError("capture binding Merge identity mismatch")
    if overlay.get("parent_ref") != merge.get("trigger_template_interface_ref") or overlay.get("parent_digest") != merge.get("trigger_template_interface_digest"):
        raise ValueError("template overlay parent identity mismatch")
    if overlay.get("template_ref") != merge.get("trigger_template_ref") or overlay.get("template_digest") != merge.get("trigger_template_digest"):
        raise ValueError("template overlay Trigger Template identity mismatch")
    if source_map.get("base_template_source_ref") != merge.get("trigger_template_source_artifact_ref") or source_map.get("base_template_source_digest") != merge.get("trigger_template_source_artifact_digest"):
        raise ValueError("SourceMap template source identity mismatch")
    regions = {item["capture_region_id"]: item for item in overlay.get("capture_regions", [])}
    region = regions.get(binding.get("capture_region_ref"))
    if region is None:
        raise ValueError("SourceMap extension requires declared capture region")
    validate_declared_capture_region(region)
    if region.get("template_ref") != merge.get("trigger_template_ref") or region.get("template_digest") != merge.get("trigger_template_digest"):
        raise ValueError("capture region Trigger Template identity mismatch")
    if binding.get("capture_region_digest") != region["digest"]:
        raise ValueError("capture region digest mismatch")
    links = []
    for item in binding.get("bindings", []):
        if item.get("capture_region_ref") != region["capture_region_id"]:
            raise ValueError("binding references undeclared capture region")
        links.append({
            "template_slot_ref": item["template_observation_slot_ref"],
            "capture_region_ref": region["capture_region_id"],
            "capture_region_digest": region["digest"],
            "emitter_binding_ref": item["capture_binding_id"],
            "runtime_event_emitter_ref": item["runtime_event_emitter_ref"],
            "semantic_role": item["semantic_role"],
        })
    return _identified(
        {
            "schema_version": "cipherlens.source_map_capture_extension.v0.1",
            "base_source_map_ref": source_map["source_map_id"],
            "base_source_map_digest": current_source_map_digest,
            "merge_ref": merge["merge_id"],
            "merge_digest": current_merge_digest,
            "template_ref": merge["trigger_template_ref"],
            "template_digest": merge["trigger_template_digest"],
            "template_source_ref": source_map["base_template_source_ref"],
            "template_source_digest": source_map["base_template_source_digest"],
            "capture_region_refs": [{"ref": region["capture_region_id"], "digest": region["digest"]}],
            "capture_links": sorted(links, key=lambda item: item["semantic_role"]),
            "base_source_map_unchanged": True,
            "protected_regions_modified": False,
            "executable_source_generated": False,
            "status": "READY",
        },
        "source-map-capture-extension",
        "extension_id",
    )
