"""Deterministic trusted renderer for Bound Source and canonical SourceMap."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from template_binding_merge.canonical import (
    bound_source_digest,
    expected_bound_source_id,
    expected_source_map_id,
    merge_digest,
    semantic_digest,
    source_map_digest,
)
from template_binding_merge.model import (
    BOUND_SOURCE_SCHEMA_VERSION,
    RENDERER_ID,
    RENDERER_VERSION,
    SOURCE_MAP_SCHEMA_VERSION,
    RegionKind,
    RenderResult,
)
from template_binding_merge.validate import (
    validate_bound_source_or_raise,
    validate_merge_or_raise,
    validate_source_map_or_raise,
)


def render_base_source(
    merge: Mapping[str, Any],
    repo_root: str | Path,
    *,
    source_artifact_ref: str = "artifacts/template_binding_merge/bound_source.c",
    fills: Mapping[str, str] | None = None,
) -> RenderResult:
    """Render only frozen mappings and declared holes; never infer semantics."""

    validate_merge_or_raise(merge)
    root = Path(repo_root).resolve()
    source_path = (root / merge["trigger_template_source_artifact_ref"]).resolve()
    source_path.relative_to(root)
    template_bytes = source_path.read_bytes()
    if hashlib.sha256(template_bytes).hexdigest() != merge["trigger_template_source_artifact_digest"]:
        raise ValueError("base template source digest changed after Merge gate")

    supplied = dict(fills or {})
    known_holes = {hole["hole_id"] for hole in merge["adaptation_holes"]}
    if set(supplied) - known_holes:
        raise ValueError("fills contain undeclared adaptation holes")

    output = bytearray()
    regions: list[dict[str, Any]] = []
    mapping_regions: dict[str, str] = {}
    identity_regions: dict[str, str] = {}

    _append_region(
        output,
        regions,
        template_bytes,
        region_id="region:base-template",
        region_kind=RegionKind.TEMPLATE_PROTECTED.value,
        protected=True,
        template_slot_refs=[],
        merge_mapping_refs=[],
        adaptation_hole_refs=[],
        observation_capture_refs=[],
    )

    for mapping in sorted(merge["slot_bindings"], key=lambda item: item["mapping_id"]):
        region_id = "region:mapping:" + _short(mapping["mapping_id"])
        payload = _record_bytes("CIPHERLENS_MAPPING", mapping)
        _append_region(
            output,
            regions,
            payload,
            region_id=region_id,
            region_kind=RegionKind.MAPPING_PROTECTED.value,
            protected=True,
            template_slot_refs=[mapping["template_slot_ref"]],
            merge_mapping_refs=[mapping["mapping_id"]],
            adaptation_hole_refs=[],
            observation_capture_refs=[
                capture["capture_binding_id"]
                for capture in merge["observation_capture_bindings"]
                if capture["observation_binding_ref"] == mapping["candidate_element_ref"]
            ],
        )
        mapping_regions[mapping["mapping_id"]] = region_id

    for identity in sorted(merge["identity_realizations"], key=lambda item: item["identity_realization_id"]):
        region_id = "region:identity:" + _short(identity["identity_realization_id"])
        _append_region(
            output,
            regions,
            _record_bytes("CIPHERLENS_IDENTITY", identity),
            region_id=region_id,
            region_kind=RegionKind.MAPPING_PROTECTED.value,
            protected=True,
            template_slot_refs=[],
            merge_mapping_refs=[],
            adaptation_hole_refs=[],
            observation_capture_refs=[],
        )
        identity_regions[identity["identity_realization_id"]] = region_id

    for hole in sorted(merge["adaptation_holes"], key=lambda item: item["hole_id"]):
        replacement = supplied.get(hole["hole_id"])
        payload = (
            replacement.encode("utf-8")
            if replacement is not None
            else f"/*__CIPHERLENS_HOLE:{hole['hole_id']}__*/".encode("utf-8")
        )
        _append_region(
            output,
            regions,
            b"\n" + payload + b"\n",
            region_id=hole["target_region_ref"],
            region_kind=RegionKind.ADAPTATION_HOLE.value,
            protected=False,
            template_slot_refs=[],
            merge_mapping_refs=[],
            adaptation_hole_refs=[hole["hole_id"]],
            observation_capture_refs=[
                capture["capture_binding_id"]
                for capture in merge["observation_capture_bindings"]
                if capture["adaptation_hole_ref"] == hole["hole_id"]
            ],
        )

    operation_order = _operation_order(merge)
    operation_mappings = {
        mapping["candidate_element_ref"]: mapping
        for mapping in merge["slot_bindings"]
        if mapping["candidate_element_kind"] == "OPERATION"
    }
    ordered_operation_records = []
    for sequence_index, operation_ref in enumerate(operation_order):
        mapping = operation_mappings[operation_ref]
        ordered_operation_records.append({
            "record_id": "operation-record:" + _short(operation_ref),
            "operation_binding_ref": operation_ref,
            "template_slot_ref": mapping["template_slot_ref"],
            "merge_mapping_ref": mapping["mapping_id"],
            "target_symbol_ref": mapping["target_semantic_ref"],
            "sequence_index": sequence_index,
            "region_ref": mapping_regions[mapping["mapping_id"]],
        })

    observation_mappings = {
        mapping["candidate_element_ref"]: mapping
        for mapping in merge["slot_bindings"]
        if mapping["candidate_element_kind"] == "OBSERVATION"
    }
    observation_records = []
    for capture in merge["observation_capture_bindings"]:
        mapping = observation_mappings[capture["observation_binding_ref"]]
        observation_records.append({
            "record_id": "observation-record:" + _short(capture["observation_binding_ref"]),
            "observation_binding_ref": capture["observation_binding_ref"],
            "capture_binding_ref": capture["capture_binding_id"],
            "semantic_source_ref": capture["semantic_source_ref"],
            "acquisition_kind": capture["acquisition_kind"],
            "phase": capture["phase"],
            "region_ref": mapping_regions[mapping["mapping_id"]],
        })

    identity_records = []
    for identity in merge["identity_realizations"]:
        identity_records.append({
            "record_id": "identity-record:" + _short(identity["identity_group_ref"]),
            "identity_group_ref": identity["identity_group_ref"],
            "storage_ref": identity["storage_ref"],
            "subject_binding_refs": list(identity["subject_binding_refs"]),
            "region_ref": identity_regions[identity["identity_realization_id"]],
        })

    current_merge_digest = merge_digest(merge)
    source_map: dict[str, Any] = {
        "schema_version": SOURCE_MAP_SCHEMA_VERSION,
        "source_map_id": "source-map:pending",
        "merge_ref": merge["merge_id"],
        "merge_digest": current_merge_digest,
        "base_template_source_ref": merge["trigger_template_source_artifact_ref"],
        "base_template_source_digest": merge["trigger_template_source_artifact_digest"],
        "regions": regions,
        "ordered_operation_records": ordered_operation_records,
        "observation_capture_records": observation_records,
        "identity_storage_records": identity_records,
    }
    source_map["source_map_id"] = expected_source_map_id(source_map)
    validate_source_map_or_raise(source_map)

    source_bytes = bytes(output)
    unresolved = sorted(known_holes - set(supplied))
    build_spec = {
        "target_scope": merge["target_scope"],
        "language": "c",
        "renderer_id": RENDERER_ID,
        "renderer_version": RENDERER_VERSION,
    }
    build_spec_digest = semantic_digest(build_spec)
    bound_source: dict[str, Any] = {
        "schema_version": BOUND_SOURCE_SCHEMA_VERSION,
        "bound_source_id": "bound-source:pending",
        "merge_ref": merge["merge_id"],
        "merge_digest": current_merge_digest,
        "source_artifact_ref": source_artifact_ref,
        "source_digest": hashlib.sha256(source_bytes).hexdigest(),
        "source_map_ref": source_map["source_map_id"],
        "source_map_digest": source_map_digest(source_map),
        "renderer_id": RENDERER_ID,
        "renderer_version": RENDERER_VERSION,
        "language": "c",
        "unresolved_hole_refs": unresolved,
        "build_spec_ref": "build-spec:" + build_spec_digest,
        "build_spec_digest": build_spec_digest,
    }
    bound_source["bound_source_id"] = expected_bound_source_id(bound_source)
    validate_bound_source_or_raise(bound_source)
    return RenderResult(source_bytes=source_bytes, source_map=source_map, bound_source=bound_source)


def _append_region(
    output: bytearray,
    regions: list[dict[str, Any]],
    payload: bytes,
    *,
    region_id: str,
    region_kind: str,
    protected: bool,
    template_slot_refs: list[str],
    merge_mapping_refs: list[str],
    adaptation_hole_refs: list[str],
    observation_capture_refs: list[str],
) -> None:
    start = len(output)
    output.extend(payload)
    end = len(output)
    regions.append({
        "region_id": region_id,
        "region_kind": region_kind,
        "source_range": {"byte_start": start, "byte_end": end},
        "protected": protected,
        "canonical_digest": hashlib.sha256(payload).hexdigest(),
        "template_slot_refs": template_slot_refs,
        "merge_mapping_refs": merge_mapping_refs,
        "adaptation_hole_refs": adaptation_hole_refs,
        "observation_capture_refs": observation_capture_refs,
    })


def _record_bytes(label: str, value: Mapping[str, Any]) -> bytes:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"\n/* {label} {body} */\n".encode("utf-8")


def _operation_order(merge: Mapping[str, Any]) -> list[str]:
    obligations = {
        item["obligation_type"]: item for item in merge["structural_obligations"]
    }
    return list(obligations["OPERATION_SEQUENCE_PRESERVED"]["ordered_refs"])


def _short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]
