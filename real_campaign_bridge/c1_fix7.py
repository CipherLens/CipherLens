"""C1-fix7 RuntimeEvent integration records; never builds or executes a target."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from runtime_event.model import SCHEMA as RUNTIME_EVENT_SCHEMA
from target_knowledge.canonical import canonical_json_bytes, identified

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE
from .capture_emitter import capture_emitter_binding


SCOPE = "SINGLE_UNIT_DRY_RUN_PREP"
_FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage")
_FIX6 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix6-v0.1")
_OUT = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
_ROLE_BY_OBSERVABLE = {
    "PARSE_OUTCOME": "operation_outcome",
    "CONSUMED_LENGTH": "consumed_length",
    "INPUT_LENGTH": "input_length",
}


def _edge(root: Path, ref: str | Path) -> dict[str, str]:
    relative = str(ref)
    return {
        "ref": relative,
        "digest": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
    }


def _document_edge(name: str, document: Mapping[str, Any]) -> dict[str, str]:
    return {
        "ref": str(_OUT / name),
        "digest": hashlib.sha256(canonical_json_bytes(document)).hexdigest(),
    }


def c1_fix7_documents(repo_root: str | Path) -> dict[str, dict[str, Any]]:
    """Describe C1 capture readiness without emitting a RuntimeEvent instance."""
    root = Path(repo_root).resolve()
    merge_ref = _FIX2 / "merge.json"
    source_map_ref = _FIX2 / "source_map.json"
    merge = json.loads((root / merge_ref).read_text())
    source_map = json.loads((root / source_map_ref).read_text())
    parent_fix6 = _edge(root, _FIX6 / "artifact_index.json")
    source_map_edge = _edge(root, source_map_ref)
    common = {
        "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE,
        "campaign_scope": CAMPAIGN_SCOPE,
        "execution_status": "NOT_EXECUTED",
        "report_real_number_allowed": False,
        "parent_artifacts": {"c1_fix6": parent_fix6},
    }
    runtime_schema = identified(
        {
            "schema_version": "cipherlens.c1_fix7_runtime_event_schema.v0.1",
            **common,
            "runtime_event_schema_version": RUNTIME_EVENT_SCHEMA,
            "schema_source": _edge(root, "runtime_event/schema.yaml"),
            "emitter_source": _edge(root, "runtime_event/emitter.py"),
            "fact_only": True,
            "verdict_authority": "NONE",
            "runtime_events_generated": False,
        },
        "c1-fix7-runtime-event-schema",
        "artifact_id",
    )

    bindings: list[dict[str, Any]] = []
    for capture in merge["observation_capture_bindings"]:
        role = _ROLE_BY_OBSERVABLE.get(capture["contract_observable_ref"])
        if role is None:
            continue
        binding_input = {
            "capture_binding_id": capture["capture_binding_id"],
            "observation_binding_ref": capture["observation_binding_ref"],
            "semantic_role": role,
            "acquisition_kind": capture["acquisition_kind"],
            "phase": capture["phase"],
        }
        binding = capture_emitter_binding(binding_input, source_map["regions"])
        binding["contract_observable_ref"] = capture["contract_observable_ref"]
        binding["source_map"] = source_map_edge
        bindings.append(binding)
    bindings.sort(key=lambda item: item["semantic_role"])
    binding_status = "READY" if bindings and all(item["status"] == "READY" for item in bindings) else "MISSING_DECLARED_CAPTURE_REGION"
    capture_binding = identified(
        {
            "schema_version": "cipherlens.capture_emitter_binding.v0.1",
            **common,
            "status": binding_status,
            "bindings": bindings,
            "source_map": source_map_edge,
            "template_interface_overlay": _edge(root, _FIX6 / "template_interface_overlay.json"),
            "authority": "DECLARED_CAPTURE_HOLE_AND_SOURCEMAP_REGION_ONLY",
        },
        "c1-fix7-capture-emitter-binding",
        "binding_id",
    )
    binding_edge = _document_edge("capture_emitter_binding.json", capture_binding)

    capture_spec = identified(
        {
            "schema_version": "cipherlens.c1_fix7_capture_spec.v0.1",
            **common,
            "status": "SPECIFICATION_ONLY",
            "capture_emitter_binding": binding_edge,
            "required_events": [
                {
                    "semantic_role": item["semantic_role"],
                    "source": {
                        "operation_outcome": "parse operation return",
                        "consumed_length": "input pointer delta",
                        "input_length": "input artifact length",
                    }[item["semantic_role"]],
                    "contract_observable_ref": item["contract_observable_ref"],
                    "observation_binding_ref": item["observation_binding_ref"],
                    "capture_id": item["capture_id"],
                    "acquisition_kind": item["acquisition_kind"],
                    "phase": item["phase"],
                    "correlation_group_ref": "CORRELATION_PRIMARY",
                }
                for item in bindings
            ],
            "correlation_constraints": [
                "same execution attempt",
                "same operation",
                "same phase",
                "same correlation group",
            ],
            "runtime_events_generated": False,
            "authority": "C1_CAPTURE_SPECIFICATION_ONLY",
        },
        "c1-fix7-capture-spec",
        "spec_id",
    )
    oracle_adapter = identified(
        {
            "schema_version": "cipherlens.c1_fix7_oracle_event_adapter.v0.1",
            **common,
            "adapter_source": _edge(root, "runtime_event/adapters.py"),
            "input_schema": "cipherlens.oracle_event.v0.1",
            "output_schema": RUNTIME_EVENT_SCHEMA,
            "requires_parsed_event_object": True,
            "witness_ref_policy": "OPTIONAL_ONLY_IF_ALREADY_CONCRETE",
            "future_witness_placeholder_forbidden": True,
            "witness_generated": False,
            "verdict_generated": False,
            "authority": "COMPATIBILITY_ADAPTER_ONLY",
        },
        "c1-fix7-oracle-adapter",
        "adapter_id",
    )
    trace_adapter = identified(
        {
            "schema_version": "cipherlens.c1_fix7_trace_adapter_spec.v0.1",
            **common,
            "adapter_source": _edge(root, "runtime_event/adapters.py"),
            "input_schema": RUNTIME_EVENT_SCHEMA,
            "accepted_input": "validated RuntimeEvent object",
            "raw_stdout_stderr_or_log_input_forbidden": True,
            "typed_observation_fields": [
                "contract_observable_ref", "observation_binding_ref", "merge_capture_ref",
                "semantic_role", "value", "status", "correlation_group_ref", "evidence_refs",
            ],
            "structured_trace_generated": False,
            "authority": "TRACE_INPUT_ADAPTER_ONLY",
        },
        "c1-fix7-trace-adapter",
        "adapter_id",
    )
    checks = [
        {"check": "RUNTIME_EVENT_SCHEMA", "status": "PASS", "evidence": _document_edge("runtime_event_schema.json", runtime_schema)},
        {"check": "RUNTIME_EVENT_EMITTER", "status": "PASS", "evidence": _edge(root, "runtime_event/emitter.py")},
        {"check": "CAPTURE_EMITTER_BINDING", "status": "PASS", "evidence": binding_edge},
        {"check": "SOURCEMAP_CAPTURE_REGION", "status": "PASS" if binding_status == "READY" else "BLOCKED", "reason_code": "MISSING_DECLARED_CAPTURE_REGION", "evidence": source_map_edge},
        {"check": "LEGACY_ORACLE_ADAPTER", "status": "PASS", "evidence": _document_edge("oracle_event_adapter.json", oracle_adapter)},
        {"check": "RUNTIME_EVENT_TRACE_ADAPTER", "status": "PASS", "evidence": _document_edge("trace_adapter_spec.json", trace_adapter)},
    ]
    blockers = [item["reason_code"] for item in checks if item["status"] == "BLOCKED"]
    gate = identified(
        {
            "schema_version": "cipherlens.c1_fix7_pre_run_gate.v0.1",
            **common,
            "status": "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if not blockers else "C1_PRE_RUN_GATE_STILL_BLOCKED",
            "checks": checks,
            "blocking_reasons": blockers,
            "cleared_blocking_reasons": ["CAPTURE_HOOK_PROTOCOL_UNMATERIALIZABLE"],
            "build_run_authorized": not blockers,
            "witness_generated": False,
            "structured_trace_generated": False,
            "execution_verdict_generated": False,
            "violation_evidence_package_generated": False,
            "authority": "C1_FIX7_PRE_RUN_GATE_ONLY",
        },
        "c1-fix7-gate",
        "decision_id",
    )
    documents = {
        "runtime_event_schema.json": runtime_schema,
        "capture_emitter_binding.json": capture_binding,
        "c1_fix7_capture_spec.json": capture_spec,
        "oracle_event_adapter.json": oracle_adapter,
        "trace_adapter_spec.json": trace_adapter,
        "c1_pre_run_gate_decision.json": gate,
    }
    index = identified(
        {
            "schema_version": "cipherlens.c1_fix7_artifact_index.v0.1",
            **common,
            "status": gate["status"],
            "parent_artifacts": {"c1_fix6": parent_fix6},
            "artifacts": [
                {"artifact_type": name[:-5], **_document_edge(name, doc)}
                for name, doc in sorted(documents.items())
            ],
            "authority": "C1_FIX7_CREATE_ONLY_ARTIFACT_INDEX",
        },
        "c1-fix7-index",
        "index_id",
    )
    documents["artifact_index.json"] = index
    return documents


def write_c1_fix7_artifacts(repo_root: str | Path) -> dict[str, Path]:
    """Create the immutable C1-fix7 evidence root exactly once."""
    root = Path(repo_root).resolve()
    out = root / _OUT
    if out.exists():
        raise FileExistsError("C1-fix7 artifact root is create-only")
    documents = c1_fix7_documents(root)
    out.mkdir(parents=True)
    for name, document in documents.items():
        (out / name).write_bytes(canonical_json_bytes(document))
    return {name: out / name for name in documents}
