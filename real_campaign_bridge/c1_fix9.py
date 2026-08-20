"""C1-fix9 canonical BoundSource materialization without source execution.

This module joins already-approved deterministic template values and capture
bindings into a target-specific specification.  It never renders C source,
invokes a compiler, starts a target process, or interprets a security result.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes, identified

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
OUTPUT = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix9-v0.1")
FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
FIX6 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix6-v0.1")
FIX7 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
FIX8 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1")
RETRY_V02 = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.2")

REQUIRED_HOLES = {
    "hole:DER_KIND": ("hole:der-kind", "enum/string", "DECLARED_PRIVATE_KEY_KIND"),
    "hole:PARSE_API_KIND": ("hole:parse-api-kind", "enum/string", "BOUND_RSA_PRIVATE_PARSE_OPERATION"),
    "hole:TRAILING_GARBAGE_BYTES": ("hole:trailing-garbage-bytes", "bytes/hex", "DECLARED_APPEND_TRAILING_DATA_INTERVENTION"),
    "hole:TRAILING_GARBAGE_LEN": ("hole:trailing-garbage-len", "integer", "BYTE_LENGTH_OF_TRAILING_GARBAGE_BYTES"),
    "hole:EXPECT_RET": ("hole:expect-ret", "integer/enum", "FIXED_SIDE_EXPECTED_REJECTION_OUTCOME"),
}
REQUIRED_ROLES = frozenset({"operation_outcome", "consumed_length", "input_length"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _load(root: Path, ref: str | Path) -> dict[str, Any]:
    return json.loads((root / ref).read_text(encoding="utf-8"))


def _file_edge(root: Path, ref: str | Path) -> dict[str, str]:
    ref_text = str(ref)
    return {
        "ref": ref_text,
        "digest": hashlib.sha256((root / ref_text).read_bytes()).hexdigest(),
    }


def _logical_edge(ref: str, digest: str) -> dict[str, str]:
    if not ref or SHA256.fullmatch(digest) is None:
        raise ValueError("logical ref requires a SHA-256 digest")
    return {"ref": ref, "digest": digest}


def _document_edge(name: str, document: Mapping[str, Any]) -> dict[str, str]:
    return {
        "ref": str(OUTPUT / name),
        "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }


def _digested(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["digest"] = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
    return result


def _common(parent_artifacts: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    return {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "NOT_EXECUTED",
        "report_real_number_allowed": False,
        "parent_artifacts": {key: dict(value) for key, value in parent_artifacts.items()},
    }


def _resolution_sources(
    hole_ref: str,
    *,
    overlay_edge: Mapping[str, str],
    resolution_edge: Mapping[str, str],
    merge_edge: Mapping[str, str],
    candidate_binding: Mapping[str, Any],
    resolved_by_hole: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, str]]:
    sources = [dict(overlay_edge), dict(resolution_edge)]
    if hole_ref in {"hole:DER_KIND", "hole:PARSE_API_KIND", "hole:TRAILING_GARBAGE_BYTES"}:
        sources.append(dict(merge_edge))
    elif hole_ref == "hole:TRAILING_GARBAGE_LEN":
        bytes_item = resolved_by_hole.get("hole:TRAILING_GARBAGE_BYTES")
        if bytes_item is not None:
            sources.append(_logical_edge(bytes_item["hole_ref"], bytes_item["digest"]))
    elif hole_ref == "hole:EXPECT_RET":
        sources.append(
            _logical_edge(
                candidate_binding["source_contract_ref"],
                candidate_binding["source_contract_digest"],
            )
        )
    return sources


def resolve_template_values(
    overlay: Mapping[str, Any],
    resolution: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    *,
    overlay_edge: Mapping[str, str],
    resolution_edge: Mapping[str, str],
    merge_edge: Mapping[str, str],
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    """Project declared values into the frozen MaterializedBoundSource names."""
    declared = {
        item.get("hole_ref"): item
        for item in overlay.get("deterministic_value_holes", [])
        if item.get("execution_blocking") is True
    }
    source_values = {
        item.get("hole_ref"): item
        for item in resolution.get("resolved_values", [])
    }
    resolved: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []
    resolved_by_hole: dict[str, dict[str, Any]] = {}

    for hole_ref, (legacy_ref, value_type, derivation_rule) in REQUIRED_HOLES.items():
        declaration = declared.get(legacy_ref)
        source = source_values.get(legacy_ref)
        if declaration is None:
            missing.append({"hole_ref": hole_ref, "reason_code": "EXECUTION_BLOCKING_HOLE_NOT_DECLARED"})
            continue
        if source is None:
            missing.append({"hole_ref": hole_ref, "reason_code": "DETERMINISTIC_VALUE_UNRESOLVED"})
            continue
        if declaration.get("expected_value_type") != value_type or source.get("value_type") != value_type:
            missing.append({"hole_ref": hole_ref, "reason_code": "DETERMINISTIC_VALUE_TYPE_MISMATCH"})
            continue
        item = {
            "hole_ref": hole_ref,
            "resolved_value": source.get("value"),
            "value_type": value_type,
            "resolver_id": "cipherlens.c1_fix9.bound_value_projector",
            "resolver_version": "v0.1",
            "derivation_rule": derivation_rule,
        }
        sources = _resolution_sources(
            hole_ref,
            overlay_edge=overlay_edge,
            resolution_edge=resolution_edge,
            merge_edge=merge_edge,
            candidate_binding=candidate_binding,
            resolved_by_hole=resolved_by_hole,
        )
        item["source_refs"] = [edge["ref"] for edge in sources]
        item["source_digests"] = [edge["digest"] for edge in sources]
        item["source_artifacts"] = sources
        digested = _digested(item)
        resolved.append(digested)
        resolved_by_hole[hole_ref] = digested

    by_hole = {item["hole_ref"]: item for item in resolved}
    bytes_item = by_hole.get("hole:TRAILING_GARBAGE_BYTES")
    length_item = by_hole.get("hole:TRAILING_GARBAGE_LEN")
    if bytes_item is not None and length_item is not None:
        try:
            actual_length = len(bytes.fromhex(str(bytes_item["resolved_value"])))
        except ValueError:
            actual_length = None
        if actual_length != length_item["resolved_value"]:
            missing.append({
                "hole_ref": "hole:TRAILING_GARBAGE_LEN",
                "reason_code": "DERIVED_BYTE_LENGTH_MISMATCH",
            })

    status = "READY" if len(resolved) == len(REQUIRED_HOLES) and not missing else "BLOCKED"
    return identified(
        {
            "schema_version": "cipherlens.resolved_template_values.v0.1",
            **_common(parent_artifacts),
            "status": status,
            "declared_execution_blocking_holes": sorted(REQUIRED_HOLES),
            "resolved_values": sorted(resolved, key=lambda item: item["hole_ref"]),
            "missing_requirements": sorted(missing, key=lambda item: (item["hole_ref"], item["reason_code"])),
            "llm_used": False,
            "rag_used": False,
            "free_text_used": False,
            "comment_parsing_used": False,
            "manual_source_used": False,
            "authority": "DETERMINISTIC_DECLARED_METADATA_PROJECTION_ONLY",
        },
        "c1-fix9-resolved-template-values",
        "resolution_id",
    )


def materialize_capture_bindings(
    capture_manifest: Mapping[str, Any],
    merge_capture_artifact: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    *,
    emitter_edge: Mapping[str, str],
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    regions = {
        item.get("capture_region_id"): item
        for item in capture_manifest.get("capture_regions", [])
    }
    merge_binding = merge_capture_artifact.get("binding", {})
    observations = {
        item.get("observation_binding_id"): item
        for item in candidate_binding.get("observation_bindings", [])
    }
    bindings: list[dict[str, Any]] = []
    missing: list[dict[str, str]] = []

    for source in merge_binding.get("bindings", []):
        role = source.get("semantic_role")
        if role not in REQUIRED_ROLES:
            continue
        region = regions.get(source.get("capture_region_ref"))
        observation = observations.get(source.get("observation_binding_ref"))
        if region is None:
            missing.append({"semantic_role": str(role), "reason_code": "DECLARED_CAPTURE_REGION_MISSING"})
            continue
        if observation is None:
            missing.append({"semantic_role": str(role), "reason_code": "OBSERVATION_BINDING_MISSING"})
            continue
        if source.get("runtime_event_emitter_ref") != emitter_edge.get("ref") or source.get("runtime_event_emitter_digest") != emitter_edge.get("digest"):
            missing.append({"semantic_role": str(role), "reason_code": "RUNTIME_EVENT_EMITTER_DIGEST_MISMATCH"})
            continue
        item = _digested({
            "capture_binding_ref": source["capture_binding_id"],
            "capture_region_ref": region["capture_region_id"],
            "capture_region_digest": region["digest"],
            "observation_binding_ref": observation["observation_binding_id"],
            "observation_binding_digest": hashlib.sha256(canonical_json_bytes(observation)).hexdigest(),
            "emitter_ref": emitter_edge["ref"],
            "emitter_digest": emitter_edge["digest"],
            "semantic_role": role,
            "acquisition_kind": source["acquisition_kind"],
            "phase": source["phase"],
            "source_map_region_ref": region["source_region_ref"],
            "source_map_region_digest": region["digest"],
            "template_slot_ref": source["template_observation_slot_ref"],
        })
        bindings.append(item)

    materialized_roles = {item["semantic_role"] for item in bindings}
    for role in sorted(REQUIRED_ROLES - materialized_roles):
        missing.append({"semantic_role": role, "reason_code": "REQUIRED_CAPTURE_BINDING_MISSING"})
    status = "READY" if materialized_roles == REQUIRED_ROLES and not missing else "BLOCKED"
    return identified(
        {
            "schema_version": "cipherlens.capture_binding_materialization.v0.1",
            **_common(parent_artifacts),
            "status": status,
            "capture_bindings": sorted(bindings, key=lambda item: item["semantic_role"]),
            "missing_requirements": sorted(missing, key=lambda item: (item["semantic_role"], item["reason_code"])),
            "runner_injection_used": False,
            "stdout_postprocessing_used": False,
            "protected_region_modified": False,
            "authority": "DECLARED_CAPTURE_REGION_AND_MERGE_BINDING_ONLY",
        },
        "c1-fix9-capture-binding-materialization",
        "materialization_id",
    )


def materialize_bound_source(
    resolved_values: Mapping[str, Any],
    capture_bindings: Mapping[str, Any],
    source_map_capture_update: Mapping[str, Any],
    merge: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    *,
    base_source_edge: Mapping[str, str],
    protected_region_modified: bool,
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    missing: list[str] = []
    if resolved_values.get("status") != "READY":
        missing.append("BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED")
    if capture_bindings.get("status") != "READY":
        missing.append("DECLARED_CAPTURE_REGION_NOT_MATERIALIZED_IN_BOUND_SOURCE")
    if source_map_capture_update.get("status") != "READY":
        missing.append("SOURCE_MAP_CAPTURE_EXTENSION_INVALID")
    if protected_region_modified or source_map_capture_update.get("protected_region_modified") is not False:
        missing.append("PROTECTED_REGION_MODIFICATION_REJECTED")
    if any(key in resolved_values for key in ("source_code", "rendered_source", "source_bytes")):
        missing.append("SOURCE_GENERATION_BYPASS_REJECTED")

    status = "READY" if not missing else "BLOCKED"
    return identified(
        {
            "schema_version": "cipherlens.materialized_bound_source.v0.1",
            **_common(parent_artifacts),
            "status": status,
            "materialization_kind": "TARGET_SPECIFIC_BOUND_TEMPLATE_SPECIFICATION",
            "template": _logical_edge(merge["trigger_template_ref"], merge["trigger_template_digest"]),
            "template_interface": _logical_edge(merge["trigger_template_interface_ref"], merge["trigger_template_interface_digest"]),
            "candidate_binding": _logical_edge(merge["candidate_binding_ref"], merge["candidate_binding_digest"]),
            "merge": _logical_edge(merge["merge_id"], hashlib.sha256(canonical_json_bytes(merge)).hexdigest()),
            "base_source_artifact": dict(base_source_edge),
            "resolved_template_values": [
                _logical_edge(item["hole_ref"], item["digest"])
                for item in resolved_values.get("resolved_values", [])
            ],
            "capture_bindings": [
                _logical_edge(item["capture_binding_ref"], item["digest"])
                for item in capture_bindings.get("capture_bindings", [])
            ],
            "source_map_input": {
                "ref": source_map_capture_update.get("update_id", "SOURCE_MAP_UPDATE_MISSING"),
                "digest": hashlib.sha256(canonical_json_bytes(source_map_capture_update)).hexdigest(),
                "status": source_map_capture_update.get("status", "BLOCKED"),
            },
            "target_scope": dict(candidate_binding["target_scope"]),
            "missing_requirements": sorted(set(missing)),
            "protected_region_modified": protected_region_modified,
            "source_generation_mode": "NOT_GENERATED_SPECIFICATION_ONLY",
            "executable_source_generated": False,
            "manual_source_generated": False,
            "free_form_generation_used": False,
            "api_discovery_used": False,
            "semantic_decision_used": False,
            "vulnerability_reasoning_used": False,
            "authority": "C1_FIX9_MATERIALIZED_BOUND_SOURCE_SPECIFICATION_ONLY",
        },
        "materialized-bound-source",
        "bound_source_id",
    )


def finalize_source_map(
    bound_source: Mapping[str, Any],
    resolved_values: Mapping[str, Any],
    capture_bindings: Mapping[str, Any],
    merge: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    *,
    bound_source_edge: Mapping[str, str],
    merge_edge: Mapping[str, str],
    base_source_map_edge: Mapping[str, str],
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    observations = {
        item.get("observation_binding_id"): item
        for item in candidate_binding.get("observation_bindings", [])
    }
    links: list[dict[str, Any]] = []
    missing: list[str] = []
    for item in capture_bindings.get("capture_bindings", []):
        observation = observations.get(item.get("observation_binding_ref"))
        if observation is None:
            missing.append("OBSERVATION_BINDING_MISSING")
            continue
        links.append(_digested({
            "template_slot_ref": item["template_slot_ref"],
            "template_slot_digest": hashlib.sha256(canonical_json_bytes({"template_slot_ref": item["template_slot_ref"]})).hexdigest(),
            "bound_value_ref": item["observation_binding_ref"],
            "bound_value_digest": item["observation_binding_digest"],
            "capture_region_ref": item["capture_region_ref"],
            "capture_region_digest": item["capture_region_digest"],
            "capture_binding_ref": item["capture_binding_ref"],
            "capture_binding_digest": item["digest"],
            "emitter_ref": item["emitter_ref"],
            "emitter_digest": item["emitter_digest"],
            "semantic_role": item["semantic_role"],
        }))
    if bound_source.get("schema_version") != "cipherlens.materialized_bound_source.v0.1" or bound_source.get("status") != "READY":
        missing.append("MATERIALIZED_BOUND_SOURCE_NOT_READY")
    if resolved_values.get("status") != "READY":
        missing.append("TEMPLATE_VALUE_MAPPING_NOT_READY")
    if capture_bindings.get("status") != "READY" or {item["semantic_role"] for item in links} != REQUIRED_ROLES:
        missing.append("CAPTURE_MAPPING_NOT_READY")
    if bound_source.get("protected_region_modified") is not False:
        missing.append("PROTECTED_REGION_MODIFICATION_REJECTED")

    capture_regions = sorted(
        {
            (item["capture_region_ref"], item["capture_region_digest"])
            for item in capture_bindings.get("capture_bindings", [])
        }
    )
    status = "READY" if not missing else "BLOCKED"
    return identified(
        {
            "schema_version": "cipherlens.final_source_map_readiness.v0.1",
            **_common(parent_artifacts),
            "status": status,
            "template_ref": merge["trigger_template_ref"],
            "template_digest": merge["trigger_template_digest"],
            "merge_ref": merge["merge_id"],
            "merge_digest": merge_edge["digest"],
            "bound_source_ref": bound_source_edge["ref"],
            "bound_source_digest": bound_source_edge["digest"],
            "base_source_map": dict(base_source_map_edge),
            "resolved_value_refs": [
                _logical_edge(item["hole_ref"], item["digest"])
                for item in resolved_values.get("resolved_values", [])
            ],
            "capture_region_refs": [
                _logical_edge(ref, digest) for ref, digest in capture_regions
            ],
            "capture_binding_refs": [
                _logical_edge(item["capture_binding_ref"], item["digest"])
                for item in capture_bindings.get("capture_bindings", [])
            ],
            "mapping_links": sorted(links, key=lambda item: item["semantic_role"]),
            "missing_requirements": sorted(set(missing)),
            "protected_region_modified": False,
            "frozen_source_map_schema_modified": False,
            "executable_source_generated": False,
            "authority": "C1_FIX9_FINAL_SOURCE_MAP_READINESS_ONLY",
        },
        "c1-fix9-final-source-map",
        "source_map_id",
    )


def execution_handoff_readiness(
    bound_source: Mapping[str, Any],
    final_source_map: Mapping[str, Any],
    merge: Mapping[str, Any],
    candidate_binding: Mapping[str, Any],
    *,
    bound_source_edge: Mapping[str, str],
    source_map_edge: Mapping[str, str],
    merge_edge: Mapping[str, str],
    candidate_binding_edge: Mapping[str, str],
    build_profile_edge: Mapping[str, str],
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    missing: list[str] = []
    if bound_source.get("schema_version") != "cipherlens.materialized_bound_source.v0.1":
        missing.append("C0_REPLAY_BOUND_SOURCE_REJECTED")
    elif bound_source.get("status") != "READY":
        missing.append("MATERIALIZED_BOUND_SOURCE_NOT_READY")
    if final_source_map.get("status") != "READY":
        missing.append("FINAL_SOURCE_MAP_NOT_READY")
    if bound_source.get("candidate_binding") != _logical_edge(merge["candidate_binding_ref"], merge["candidate_binding_digest"]):
        missing.append("CANDIDATE_BINDING_LINEAGE_MISMATCH")
    if (
        candidate_binding.get("binding_id") != merge.get("candidate_binding_ref")
        or hashlib.sha256(canonical_json_bytes(candidate_binding)).hexdigest()
        != merge.get("candidate_binding_digest")
    ):
        missing.append("CANDIDATE_BINDING_DIGEST_MISMATCH")
    if bound_source.get("merge", {}).get("ref") != merge.get("merge_id"):
        missing.append("MERGE_LINEAGE_MISMATCH")
    status = "READY" if not missing else "BLOCKED"
    return identified(
        {
            "schema_version": "cipherlens.execution_handoff_readiness.v0.1",
            **_common(parent_artifacts),
            "status": status,
            "bound_source": dict(bound_source_edge),
            "source_map": dict(source_map_edge),
            "candidate_binding": _logical_edge(merge["candidate_binding_ref"], merge["candidate_binding_digest"]),
            "candidate_binding_artifact": dict(candidate_binding_edge),
            "merge": _logical_edge(merge["merge_id"], merge_edge["digest"]),
            "merge_artifact": dict(merge_edge),
            "build_profile": dict(build_profile_edge),
            "claim_boundary": {
                "scope": SCOPE,
                "campaign_scope": CAMPAIGN_SCOPE,
                "allowed_next_stage": "C1_RETRY_ONLY" if status == "READY" else "C1_FIX_ONLY",
                "full_campaign_allowed": False,
                "report_real_number_allowed": False,
                "vulnerability_claim_allowed": False,
            },
            "missing_requirements": sorted(set(missing)),
            "build_attempted": False,
            "run_attempted": False,
            "authority": "C1_FIX9_EXECUTION_HANDOFF_READINESS_ONLY",
        },
        "c1-fix9-execution-handoff-readiness",
        "readiness_id",
    )


def _gate_document(
    bound_source: Mapping[str, Any],
    capture_bindings: Mapping[str, Any],
    final_source_map: Mapping[str, Any],
    handoff: Mapping[str, Any],
    *,
    bound_source_edge: Mapping[str, str],
    capture_edge: Mapping[str, str],
    source_map_edge: Mapping[str, str],
    handoff_edge: Mapping[str, str],
    parent_artifacts: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    checks = [
        {"check": "BOUND_SOURCE_MATERIALIZED", "status": "PASS" if bound_source.get("status") == "READY" else "BLOCKED", "evidence": dict(bound_source_edge)},
        {"check": "CAPTURE_BINDINGS_MATERIALIZED", "status": "PASS" if capture_bindings.get("status") == "READY" else "BLOCKED", "evidence": dict(capture_edge)},
        {"check": "SOURCE_MAP_FINALIZED", "status": "PASS" if final_source_map.get("status") == "READY" else "BLOCKED", "evidence": dict(source_map_edge)},
        {"check": "EXECUTION_HANDOFF_READY", "status": "PASS" if handoff.get("status") == "READY" else "BLOCKED", "evidence": dict(handoff_edge)},
    ]
    blockers = [item["check"] for item in checks if item["status"] != "PASS"]
    ready = not blockers
    return identified(
        {
            "schema_version": "cipherlens.c1_fix9_pre_run_gate.v0.1",
            **_common(parent_artifacts),
            "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if ready else "C1_PRE_RUN_GATE_STILL_BLOCKED",
            "checks": checks,
            "blocking_reasons": blockers,
            "cleared_blocking_reasons": [
                "BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED",
                "DECLARED_CAPTURE_REGION_NOT_MATERIALIZED_IN_BOUND_SOURCE",
            ] if ready else [],
            "allowed_next_stage": "C1_RETRY_ONLY" if ready else "C1_FIX_ONLY",
            "c1_retry_allowed": ready,
            "full_campaign_allowed": False,
            "build_attempted": False,
            "run_attempted": False,
            "target_binary_started": False,
            "runtime_event_generated": False,
            "witness_generated": False,
            "trace_generated": False,
            "projection_generated": False,
            "relation_evaluation_generated": False,
            "execution_verdict_generated": False,
            "violation_evidence_package_generated": False,
            "authority": "C1_FIX9_PRE_RUN_GATE_ONLY",
        },
        "c1-fix9-pre-run-gate",
        "decision_id",
    )


def c1_fix9_documents(repo_root: str | Path) -> dict[str, dict[str, Any]]:
    """Build the seven create-only C1-fix9 documents in memory."""
    root = Path(repo_root).resolve()
    parent_artifacts = {
        "c1_retry_v0_2": _file_edge(root, RETRY_V02 / "artifact_index.json"),
        "c1_fix8": _file_edge(root, FIX8 / "artifact_index.json"),
        "c1_fix7": _file_edge(root, FIX7 / "artifact_index.json"),
    }
    overlay = _load(root, FIX6 / "template_interface_overlay.json")
    resolution = _load(root, FIX6 / "deterministic_value_resolution.json")
    capture_manifest = _load(root, FIX8 / "capture_region_manifest.json")
    merge_capture = _load(root, FIX8 / "merge_capture_binding.json")
    source_map_capture = _load(root, FIX8 / "source_map_capture_update.json")
    merge = _load(root, FIX2 / "merge.json")
    candidate = _load(root, FIX2 / "candidate_binding.json")

    merge_edge = _file_edge(root, FIX2 / "merge.json")
    candidate_edge = _file_edge(root, FIX2 / "candidate_binding.json")
    values = resolve_template_values(
        overlay,
        resolution,
        candidate,
        overlay_edge=_file_edge(root, FIX6 / "template_interface_overlay.json"),
        resolution_edge=_file_edge(root, FIX6 / "deterministic_value_resolution.json"),
        merge_edge=merge_edge,
        parent_artifacts=parent_artifacts,
    )
    captures = materialize_capture_bindings(
        capture_manifest,
        merge_capture,
        candidate,
        emitter_edge=_file_edge(root, "runtime_event/emitter.py"),
        parent_artifacts=parent_artifacts,
    )
    bound_source = materialize_bound_source(
        values,
        captures,
        source_map_capture,
        merge,
        candidate,
        base_source_edge=_file_edge(root, FIX2 / "bound_source.c"),
        protected_region_modified=False,
        parent_artifacts=parent_artifacts,
    )
    bound_source_edge = _document_edge("bound_source_materialization.json", bound_source)
    final_map = finalize_source_map(
        bound_source,
        values,
        captures,
        merge,
        candidate,
        bound_source_edge=bound_source_edge,
        merge_edge=merge_edge,
        base_source_map_edge=_file_edge(root, FIX2 / "source_map.json"),
        parent_artifacts=parent_artifacts,
    )
    final_map_edge = _document_edge("source_map_finalization.json", final_map)
    handoff = execution_handoff_readiness(
        bound_source,
        final_map,
        merge,
        candidate,
        bound_source_edge=bound_source_edge,
        source_map_edge=final_map_edge,
        merge_edge=merge_edge,
        candidate_binding_edge=candidate_edge,
        build_profile_edge=_file_edge(root, FIX4 / "build_profile_alignment.json"),
        parent_artifacts=parent_artifacts,
    )
    captures_edge = _document_edge("capture_binding_materialization.json", captures)
    handoff_edge = _document_edge("execution_handoff_readiness.json", handoff)
    gate = _gate_document(
        bound_source,
        captures,
        final_map,
        handoff,
        bound_source_edge=bound_source_edge,
        capture_edge=captures_edge,
        source_map_edge=final_map_edge,
        handoff_edge=handoff_edge,
        parent_artifacts=parent_artifacts,
    )
    documents = {
        "bound_source_materialization.json": bound_source,
        "resolved_template_values.json": values,
        "capture_binding_materialization.json": captures,
        "source_map_finalization.json": final_map,
        "execution_handoff_readiness.json": handoff,
        "c1_pre_run_gate_decision.json": gate,
    }
    index = identified(
        {
            "schema_version": "cipherlens.c1_fix9_artifact_index.v0.1",
            **_common(parent_artifacts),
            "status": gate["status"],
            "artifacts": [
                {"artifact_type": name[:-5], **_document_edge(name, document)}
                for name, document in sorted(documents.items())
            ],
            "create_only": True,
            "authority": "C1_FIX9_CREATE_ONLY_ARTIFACT_INDEX",
        },
        "c1-fix9-artifact-index",
        "index_id",
    )
    documents["artifact_index.json"] = index
    return documents


def write_c1_fix9_artifacts(repo_root: str | Path) -> dict[str, Path]:
    root = Path(repo_root).resolve()
    output = root / OUTPUT
    if output.exists():
        raise FileExistsError("C1-fix9 artifact root is create-only")
    documents = c1_fix9_documents(root)
    output.mkdir(parents=True)
    for name, document in documents.items():
        (output / name).write_bytes(canonical_json_bytes(document))
    return {name: output / name for name in documents}
