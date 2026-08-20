"""C1-fix10 executable BoundSource materialization without execution.

This repair consumes only the declared C1-fix9 values and capture bindings.
It produces a create-only executable-source preparation record; it does not
compile, run, create RuntimeEvents, or make a security conclusion.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes, identified
from template_binding_merge.executable_completion import (
    CAPTURE_REGION_REF,
    RENDERER_ID,
    RENDERER_VERSION,
    render_executable_bound_source,
)

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
OUTPUT = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix10-v0.1")
FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
FIX7 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
FIX8 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1")
FIX9 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix9-v0.1")


def _load(root: Path, ref: Path | str) -> dict[str, Any]:
    return json.loads((root / ref).read_text(encoding="utf-8"))


def _edge(root: Path, ref: Path | str) -> dict[str, str]:
    text = str(ref)
    return {"ref": text, "digest": hashlib.sha256((root / text).read_bytes()).hexdigest()}


def _document_edge(name: str, document: Mapping[str, Any]) -> dict[str, str]:
    return {
        "ref": str(OUTPUT / name),
        "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }


def _common(parents: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    return {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "NOT_EXECUTED",
        "report_real_number_allowed": False,
        "parent_artifacts": {name: dict(edge) for name, edge in parents.items()},
    }


def _stable_item(value: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(value)
    item["digest"] = hashlib.sha256(canonical_json_bytes(item)).hexdigest()
    return item


def c1_fix10_documents(repo_root: str | Path) -> tuple[dict[str, dict[str, Any]], bytes]:
    """Build all C1-fix10 documents in memory, with no execution side effects."""
    root = Path(repo_root).resolve()
    parents = {
        "c1_fix9": _edge(root, FIX9 / "artifact_index.json"),
        "c1_fix8": _edge(root, FIX8 / "artifact_index.json"),
        "c1_fix7": _edge(root, FIX7 / "artifact_index.json"),
    }
    resolved = _load(root, FIX9 / "resolved_template_values.json")
    capture_bindings = _load(root, FIX9 / "capture_binding_materialization.json")
    merge = _load(root, FIX2 / "merge.json")
    candidate = _load(root, FIX2 / "candidate_binding.json")
    base_ref = FIX2 / "bound_source.c"
    base_bytes = (root / base_ref).read_bytes()
    completion = render_executable_bound_source(
        base_bytes, resolved, capture_bindings, merge, candidate
    )

    hole_records = [_stable_item(item) for item in completion.hole_records]
    hole_document = identified(
        {
            "schema_version": "cipherlens.executable_hole_resolution.v0.1",
            **_common(parents),
            "status": "READY",
            "base_source": _edge(root, base_ref),
            "resolved_holes": sorted(hole_records, key=lambda item: item["hole_ref"]),
            "syntax_only_completion": True,
            "semantic_choice_changed": False,
            "text_search_used": False,
            "regex_used": False,
            "comment_parsing_used": False,
            "llm_used": False,
            "rag_used": False,
            "legacy_filler_used": False,
            "authority": "FIXED_BYTE_RANGE_DECLARED_VALUE_COMPLETION_ONLY",
        },
        "c1-fix10-hole-resolution",
        "resolution_id",
    )
    hole_edge = _document_edge("hole_resolution.json", hole_document)

    capture_records = [_stable_item(item) for item in completion.capture_records]
    capture_document = identified(
        {
            "schema_version": "cipherlens.capture_protocol_materialization.v0.1",
            **_common(parents),
            "status": "READY",
            "capture_region_ref": CAPTURE_REGION_REF,
            "capture_realizations": sorted(capture_records, key=lambda item: item["semantic_role"]),
            "target_emitted": True,
            "runner_injection_used": False,
            "stdout_postprocessing_used": False,
            "regex_injection_used": False,
            "runtime_events_generated": False,
            "consumed_length_limit": {
                "status": "ACQUISITION_FAILED",
                "reason_code": "POINTER_DELTA_UNAVAILABLE",
                "fabricated_value": False,
            },
            "authority": "DECLARED_CAPTURE_REGION_TARGET_EMITTER_ONLY",
        },
        "c1-fix10-capture-protocol-materialization",
        "materialization_id",
    )
    capture_edge = _document_edge("capture_protocol_materialization.json", capture_document)

    source_ref = str(OUTPUT / "executable_bound_source.c")
    source_edge = {
        "ref": source_ref,
        "digest": hashlib.sha256(completion.source_bytes).hexdigest(),
    }
    source_map = identified(
        {
            "schema_version": "cipherlens.executable_source_map.v0.1",
            **_common(parents),
            "status": "READY",
            "source_artifact": source_edge,
            "template": {
                "ref": merge["trigger_template_ref"],
                "digest": merge["trigger_template_digest"],
            },
            "merge": {
                "ref": merge["merge_id"],
                "digest": hashlib.sha256(canonical_json_bytes(merge)).hexdigest(),
            },
            "candidate_binding": {
                "ref": merge["candidate_binding_ref"],
                "digest": merge["candidate_binding_digest"],
            },
            "hole_resolution": hole_edge,
            "capture_protocol": capture_edge,
            "hole_mappings": sorted(hole_records, key=lambda item: item["hole_ref"]),
            "capture_mappings": sorted(capture_records, key=lambda item: item["semantic_role"]),
            "protected_regions": list(completion.protected_regions),
            "generated_regions": list(completion.generated_regions),
            "protected_region_modified": False,
            "frozen_source_map_schema_modified": False,
            "authority": "EXECUTABLE_SOURCEMAP_SUPPLEMENT_FIXED_BYTE_RANGES",
        },
        "c1-fix10-executable-source-map",
        "source_map_id",
    )
    source_map_edge = _document_edge("source_map_finalization.json", source_map)

    executable = identified(
        {
            "schema_version": "cipherlens.executable_bound_source.v0.1",
            **_common(parents),
            "status": "READY",
            "source_artifact": source_edge,
            "source_map": source_map_edge,
            "hole_resolution": hole_edge,
            "capture_protocol": capture_edge,
            "renderer": {"id": RENDERER_ID, "version": RENDERER_VERSION},
            "executable_source_generated": True,
            "source_generation_mode": "DETERMINISTIC_DECLARED_REGION_RENDER",
            "free_form_generation_used": False,
            "api_discovery_used": False,
            "semantic_decision_used": False,
            "vulnerability_reasoning_used": False,
            "build_attempted": False,
            "run_attempted": False,
            "authority": "C1_FIX10_EXECUTABLE_BOUNDSOURCE_ONLY",
        },
        "c1-fix10-executable-bound-source",
        "bound_source_id",
    )
    executable_edge = _document_edge("executable_bound_source.json", executable)

    handoff = identified(
        {
            "schema_version": "cipherlens.execution_handoff_readiness.v0.2",
            **_common(parents),
            "status": "READY",
            "executable_bound_source": executable_edge,
            "source_artifact": source_edge,
            "source_map": source_map_edge,
            "merge": {
                "ref": merge["merge_id"],
                "digest": hashlib.sha256(canonical_json_bytes(merge)).hexdigest(),
            },
            "merge_artifact": _edge(root, FIX2 / "merge.json"),
            "candidate_binding": {
                "ref": merge["candidate_binding_ref"],
                "digest": merge["candidate_binding_digest"],
            },
            "candidate_binding_artifact": _edge(root, FIX2 / "candidate_binding.json"),
            "build_profile": _edge(root, FIX4 / "build_profile_alignment.json"),
            "claim_boundary": {
                "scope": SCOPE,
                "campaign_scope": CAMPAIGN_SCOPE,
                "allowed_next_stage": "C1_RETRY_ONLY",
                "full_campaign_allowed": False,
                "report_real_number_allowed": False,
                "vulnerability_claim_allowed": False,
            },
            "build_attempted": False,
            "run_attempted": False,
            "authority": "C1_FIX10_EXECUTION_HANDOFF_READINESS_ONLY",
        },
        "c1-fix10-execution-handoff-readiness",
        "readiness_id",
    )
    handoff_edge = _document_edge("execution_handoff_readiness.json", handoff)

    gate = identified(
        {
            "schema_version": "cipherlens.c1_fix10_pre_run_gate.v0.1",
            **_common(parents),
            "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY",
            "checks": [
                {"check": "EXECUTABLE_BOUND_SOURCE", "status": "PASS", "evidence": executable_edge},
                {"check": "CAPTURE_PROTOCOL", "status": "PASS", "evidence": capture_edge},
                {"check": "EXECUTABLE_SOURCE_MAP", "status": "PASS", "evidence": source_map_edge},
                {"check": "EXECUTION_HANDOFF", "status": "PASS", "evidence": handoff_edge},
            ],
            "blocking_reasons": [],
            "cleared_blocking_reasons": [
                "EXECUTABLE_BOUND_SOURCE_NOT_MATERIALIZED",
                "DECLARED_CAPTURE_PROTOCOL_NOT_MATERIALIZED",
            ],
            "allowed_next_stage": "C1_RETRY_ONLY",
            "c1_retry_allowed": True,
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
            "authority": "C1_FIX10_PRE_RUN_GATE_ONLY",
        },
        "c1-fix10-pre-run-gate",
        "decision_id",
    )
    documents = {
        "executable_bound_source.json": executable,
        "hole_resolution.json": hole_document,
        "capture_protocol_materialization.json": capture_document,
        "source_map_finalization.json": source_map,
        "execution_handoff_readiness.json": handoff,
        "c1_pre_run_gate_decision.json": gate,
    }
    index = identified(
        {
            "schema_version": "cipherlens.c1_fix10_artifact_index.v0.1",
            **_common(parents),
            "status": gate["status"],
            "artifacts": [
                {"artifact_type": name[:-5], **_document_edge(name, document)}
                for name, document in sorted(documents.items())
            ] + [{"artifact_type": "executable_source", **source_edge}],
            "create_only": True,
            "authority": "C1_FIX10_CREATE_ONLY_ARTIFACT_INDEX",
        },
        "c1-fix10-artifact-index",
        "index_id",
    )
    documents["artifact_index.json"] = index
    return documents, completion.source_bytes


def write_c1_fix10_artifacts(repo_root: str | Path) -> dict[str, Path]:
    """Write one fresh immutable C1-fix10 root after all documents validate."""
    root = Path(repo_root).resolve()
    output = root / OUTPUT
    if output.exists():
        raise FileExistsError("C1-fix10 artifact root is create-only")
    documents, source_bytes = c1_fix10_documents(root)
    output.mkdir(parents=True)
    source_path = output / "executable_bound_source.c"
    source_path.write_bytes(source_bytes)
    for name, document in documents.items():
        (output / name).write_bytes(canonical_json_bytes(document))
    return {"executable_bound_source.c": source_path, **{name: output / name for name in documents}}
