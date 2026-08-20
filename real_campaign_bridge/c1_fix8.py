"""C1-fix8 declared capture lifecycle, without source generation or execution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes, identified
from template_binding_merge.capture_region import (
    make_merge_capture_binding,
    make_source_map_capture_extension,
)
from trigger_template_interface.capture_region import (
    CAPTURE_REGION_ID,
    make_capture_region_overlay,
    make_declared_capture_region,
)

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE
from .capture_emitter import capture_emitter_binding


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
_FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
_FIX6 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix6-v0.1")
_FIX7 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
_OUT = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1")


def _edge(root: Path, ref: str | Path) -> dict[str, str]:
    relative = str(ref)
    return {"ref": relative, "digest": hashlib.sha256((root / relative).read_bytes()).hexdigest()}


def _document_edge(name: str, document: Mapping[str, Any]) -> dict[str, str]:
    return {
        "ref": str(_OUT / name),
        "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }


def c1_fix8_documents(repo_root: str | Path) -> dict[str, dict[str, Any]]:
    """Build preparation-only capture lifecycle documents in memory."""
    root = Path(repo_root).resolve()
    merge = json.loads((root / _FIX2 / "merge.json").read_text())
    source_map = json.loads((root / _FIX2 / "source_map.json").read_text())
    resolution = json.loads((root / _FIX6 / "deterministic_value_resolution.json").read_text())
    parent_fix6 = _edge(root, _FIX6 / "artifact_index.json")
    parent_fix7 = _edge(root, _FIX7 / "artifact_index.json")
    template_parent = {
        "ref": merge["trigger_template_interface_ref"],
        "digest": merge["trigger_template_interface_digest"],
    }
    common = {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "NOT_EXECUTED",
        "report_real_number_allowed": False,
        "parent_artifacts": {"c1_fix6": parent_fix6, "c1_fix7": parent_fix7},
    }
    region = make_declared_capture_region(
        capture_region_id=CAPTURE_REGION_ID,
        template_ref=merge["trigger_template_ref"],
        template_digest=merge["trigger_template_digest"],
        source_region_ref=CAPTURE_REGION_ID,
        semantic_roles=["operation_outcome", "consumed_length", "input_length"],
        phase="AFTER_STEP",
        operation_ref="OPERATION_0_PARSE_KEY",
        multiplicity="ONE_OR_MORE",
        provenance_refs=[template_parent, parent_fix6, parent_fix7],
    )
    region_manifest = identified(
        {
            "schema_version": "cipherlens.c1_fix8_capture_region_manifest.v0.1",
            **common,
            "template_parent": template_parent,
            "capture_regions": [region],
            "semantic_position": "AFTER_PARSE_BEFORE_CLEANUP",
            "arbitrary_source_range_allowed": False,
            "runner_injection_allowed": False,
            "regex_injection_allowed": False,
        },
        "c1-fix8-capture-region-manifest",
        "manifest_id",
    )
    overlay = make_capture_region_overlay(
        parent_ref=template_parent["ref"],
        parent_digest=template_parent["digest"],
        template_ref=merge["trigger_template_ref"],
        template_digest=merge["trigger_template_digest"],
        capture_regions=[region],
    )
    overlay_document = identified(
        {
            "schema_version": "cipherlens.c1_fix8_template_overlay_artifact.v0.1",
            **common,
            "template_parent": template_parent,
            "overlay": overlay,
            "base_manifest_modified": False,
        },
        "c1-fix8-template-overlay-artifact",
        "artifact_id",
    )
    emitter_edge = _edge(root, "runtime_event/emitter.py")
    binding = make_merge_capture_binding(
        merge,
        region,
        emitter_ref=emitter_edge["ref"],
        emitter_digest=emitter_edge["digest"],
    )
    emitter_bindings = [
        capture_emitter_binding(
            {
                "capture_binding_id": item["capture_binding_id"],
                "observation_binding_ref": item["observation_binding_ref"],
                "semantic_role": item["semantic_role"],
                "acquisition_kind": item["acquisition_kind"],
                "phase": item["phase"],
            },
            [region],
            emitter_ref=emitter_edge["ref"],
        )
        for item in binding["bindings"]
    ]
    binding_document = identified(
        {
            "schema_version": "cipherlens.c1_fix8_merge_capture_binding_artifact.v0.1",
            **common,
            "status": "READY" if all(item["status"] == "READY" for item in emitter_bindings) else "BLOCKED",
            "binding": binding,
            "capture_emitter_bindings": emitter_bindings,
            "contract_modified": False,
            "candidate_binding_modified": False,
            "api_reselected": False,
        },
        "c1-fix8-merge-capture-binding-artifact",
        "artifact_id",
    )
    source_map_extension = make_source_map_capture_extension(source_map, merge, overlay, binding)
    source_map_document = identified(
        {
            "schema_version": "cipherlens.c1_fix8_source_map_capture_update.v0.1",
            **common,
            "status": source_map_extension["status"],
            "base_source_map": _edge(root, _FIX2 / "source_map.json"),
            "extension": source_map_extension,
            "frozen_source_map_schema_modified": False,
            "protected_region_modified": False,
        },
        "c1-fix8-source-map-capture-update",
        "update_id",
    )
    checks = [
        {"check": "EXECUTION_BLOCKING_TEMPLATE_VALUES", "status": "PASS" if resolution.get("status") == "COMPLETE" and not resolution.get("unresolved") else "BLOCKED", "evidence": _edge(root, _FIX6 / "deterministic_value_resolution.json")},
        {"check": "DECLARED_CAPTURE_REGION", "status": "PASS", "evidence": _document_edge("capture_region_manifest.json", region_manifest)},
        {"check": "MERGE_CAPTURE_BINDING", "status": "PASS" if binding_document["status"] == "READY" else "BLOCKED", "evidence": _document_edge("merge_capture_binding.json", binding_document)},
        {"check": "SOURCE_MAP_CAPTURE_REFS", "status": "PASS" if source_map_document["status"] == "READY" else "BLOCKED", "evidence": _document_edge("source_map_capture_update.json", source_map_document)},
        {"check": "RUNTIME_EVENT_EMITTER_REF", "status": "PASS", "evidence": emitter_edge},
    ]
    blockers = [item["check"] for item in checks if item["status"] != "PASS"]
    readiness = identified(
        {
            "schema_version": "cipherlens.c1_fix8_bound_source_readiness.v0.1",
            **common,
            "status": "READY" if not blockers else "BLOCKED",
            "checks": checks,
            "blocking_reasons": blockers,
            "bound_source_generated": False,
            "executable_source_generated": False,
            "fake_source_generated": False,
            "readiness_scope": "C1_RETRY_MATERIALIZATION_ONLY",
        },
        "c1-fix8-bound-source-readiness",
        "readiness_id",
    )
    gate_checks = [
        {"check": "DECLARED_CAPTURE_REGION", "status": "PASS", "evidence": _document_edge("capture_region_manifest.json", region_manifest)},
        {"check": "SOURCE_MAP_REFERENCES_CAPTURE_REGION", "status": "PASS" if source_map_document["status"] == "READY" else "BLOCKED", "evidence": _document_edge("source_map_capture_update.json", source_map_document)},
        {"check": "MERGE_BINDING_REFERENCES_CAPTURE_REGION", "status": "PASS" if binding_document["status"] == "READY" else "BLOCKED", "evidence": _document_edge("merge_capture_binding.json", binding_document)},
        {"check": "RUNTIME_EVENT_EMITTER_REFERENCE", "status": "PASS", "evidence": emitter_edge},
        {"check": "BOUND_SOURCE_READINESS", "status": "PASS" if readiness["status"] == "READY" else "BLOCKED", "evidence": _document_edge("bound_source_readiness.json", readiness)},
    ]
    gate_blockers = [item["check"] for item in gate_checks if item["status"] != "PASS"]
    gate = identified(
        {
            "schema_version": "cipherlens.c1_fix8_pre_run_gate.v0.1",
            **common,
            "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if not gate_blockers else "C1_PRE_RUN_GATE_STILL_BLOCKED",
            "checks": gate_checks,
            "blocking_reasons": gate_blockers,
            "cleared_blocking_reasons": ["CAPTURE_HOOK_PROTOCOL_UNMATERIALIZABLE", "MISSING_DECLARED_CAPTURE_REGION"],
            "allowed_next_stage": "C1_RETRY_ONLY" if not gate_blockers else "C1_FIX_ONLY",
            "c1_retry_allowed": not gate_blockers,
            "full_campaign_allowed": False,
            "build_run_attempted": False,
            "runtime_event_generated": False,
            "witness_generated": False,
            "structured_trace_generated": False,
            "projection_generated": False,
            "relation_evaluation_generated": False,
            "execution_verdict_generated": False,
            "violation_evidence_package_generated": False,
            "authority": "C1_FIX8_PRE_RUN_GATE_ONLY",
        },
        "c1-fix8-gate",
        "decision_id",
    )
    documents = {
        "capture_region_manifest.json": region_manifest,
        "template_overlay.json": overlay_document,
        "merge_capture_binding.json": binding_document,
        "source_map_capture_update.json": source_map_document,
        "bound_source_readiness.json": readiness,
        "c1_pre_run_gate_decision.json": gate,
    }
    index = identified(
        {
            "schema_version": "cipherlens.c1_fix8_artifact_index.v0.1",
            **common,
            "status": gate["status"],
            "artifacts": [
                {"artifact_type": name[:-5], **_document_edge(name, document)}
                for name, document in sorted(documents.items())
            ],
            "create_only": True,
            "authority": "C1_FIX8_CREATE_ONLY_ARTIFACT_INDEX",
        },
        "c1-fix8-index",
        "index_id",
    )
    documents["artifact_index.json"] = index
    return documents


def write_c1_fix8_artifacts(repo_root: str | Path) -> dict[str, Path]:
    root = Path(repo_root).resolve()
    out = root / _OUT
    if out.exists():
        raise FileExistsError("C1-fix8 artifact root is create-only")
    documents = c1_fix8_documents(root)
    out.mkdir(parents=True)
    for name, document in documents.items():
        (out / name).write_bytes(canonical_json_bytes(document))
    return {name: out / name for name in documents}
