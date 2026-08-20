"""Fail-closed materialization gate for the sole C1 retry unit.

The gate deliberately stops before execution when the immutable BoundSource
cannot be compiled and instrumented without changing protected regions.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from execution_model.canonical import artifact_digest
from target_knowledge.canonical import canonical_json_bytes, identified

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE, SCOPE


_FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1")
_FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
_FIX7 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix7-v0.1")
_FIX8 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix8-v0.1")
_FIX9 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix9-v0.1")
_OUTPUT = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1")
_OUTPUT_V02 = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.2")
_OUTPUT_V03 = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.3")
_MASK = re.compile(r"\[(?:DER_KIND|PARSE_API_KIND|TRAILING_GARBAGE_BYTES|TRAILING_GARBAGE_LEN|EXPECT_RET)\]")


def _bytes_edge(root: Path, ref: str) -> dict[str, str]:
    payload = (root / ref).read_bytes()
    return {"ref": ref, "digest": hashlib.sha256(payload).hexdigest()}


def _read(root: Path, ref: str) -> tuple[dict[str, Any], dict[str, str]]:
    edge = _bytes_edge(root, ref)
    return json.loads((root / ref).read_text()), edge


def _check(name: str, passed: bool, reason: str, edge: Mapping[str, str] | None = None) -> dict[str, Any]:
    return {"check": name, "status": "PASS" if passed else "BLOCKED", "reason_code": reason, "evidence_refs": [dict(edge)] if edge else []}


def evaluate_c1_retry_gate(repo_root: str | Path) -> dict[str, Any]:
    """Validate C1-fix4 inputs without starting a compiler or a process."""

    root = Path(repo_root).resolve()
    population_ref = "artifacts/pipeline_v2/real_campaign_preflight/population_manifests/CLV2-RQ4-PILOT-001.json"
    population, population_edge = _read(root, population_ref)
    lineage_ref = str(_FIX2 / "c1_lineage_readiness.json")
    lineage, lineage_edge = _read(root, lineage_ref)
    source_ref = str(_FIX2 / "lineage/bound_source.c")
    source_edge = _bytes_edge(root, source_ref)
    source_bytes = (root / source_ref).read_text()
    fix4_gate_ref = str(_FIX4 / "c1_pre_run_gate_decision.json")
    fix4_gate, fix4_gate_edge = _read(root, fix4_gate_ref)
    provenance_ref = str(_FIX4 / "library_build_provenance_record.json")
    provenance, provenance_edge = _read(root, provenance_ref)
    raw_inventory_ref = str(_FIX4 / "raw_artifact_inventory.json")
    raw_inventory, raw_inventory_edge = _read(root, raw_inventory_ref)
    capture_ref = "artifacts/pipeline_v2/real_campaign_preflight/capture_bridge/readiness_7d_b.json"
    capture, capture_edge = _read(root, capture_ref)
    build_ref = str(_FIX2 / "build_spec.json")
    build_spec, build_edge = _read(root, build_ref)

    units = [item for item in population.get("units", []) if item.get("unit_id") == APPROVED_UNIT_ID]
    raw_ok = all(
        (root / item["ref"]).is_file()
        and hashlib.sha256((root / item["ref"]).read_bytes()).hexdigest() == item["digest"]
        for item in raw_inventory.get("artifacts", [])
    )
    lineage_ok = all(
        (root / item["ref"]).is_file()
        and hashlib.sha256((root / item["ref"]).read_bytes()).hexdigest() == item["digest"]
        for item in lineage.get("lineage_artifacts", {}).values()
    )
    roles = set(capture.get("cases", {}).get("0020", {}).get("required_roles", []))
    checks = [
        _check("APPROVED_UNIT", len(units) == 1 and len(population.get("units", [])) == 11, "APPROVED_TRACK_A_0020_FIXED_UNIT_VERIFIED", population_edge),
        _check("LINEAGE", lineage.get("status") == "COMPLETE_NOT_EXECUTED" and lineage_ok, "CANONICAL_LINEAGE_DIGEST_VERIFIED", lineage_edge),
        _check("FIX4_PROVENANCE", fix4_gate.get("status") == "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" and provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY" and raw_ok, "REBUILT_LIBRARY_PROVENANCE_VERIFIED", provenance_edge),
        _check("BUILDSPEC", build_spec.get("schema_version") == "cipherlens.build_spec.v0.1" and build_spec.get("execution_handoff_ref"), "BUILDSPEC_FROM_EXECUTION_HANDOFF_VERIFIED", build_edge),
        _check("CAPTURE_SPEC", roles == {"operation_outcome", "consumed_length", "input_length"} and capture.get("cases", {}).get("0020", {}).get("correlation_requirement") == "shared operation/input correlation group", "CAPTURE_ROLES_AND_CORRELATION_VERIFIED", capture_edge),
        _check("BOUND_SOURCE_VALUES", not _MASK.search(source_bytes), "BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", source_edge),
        _check("BOUND_SOURCE_MARKER", "ORACLE_EVENT_V0_1" in source_bytes, "ORACLE_EVENT_CAPTURE_NOT_EMBEDDED", source_edge),
    ]
    blockers = [item["reason_code"] for item in checks if item["status"] != "PASS"]
    return identified({
        "schema_version": "cipherlens.c1_retry_pre_run_gate.v0.1", "unit_id": APPROVED_UNIT_ID,
        "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_PRE_RUN_GATE_PASSED" if not blockers else "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "checks": checks, "blocking_reasons": blockers,
        "input_artifacts": {"population": population_edge, "lineage": lineage_edge, "bound_source": source_edge, "fix4_gate": fix4_gate_edge, "provenance": provenance_edge, "raw_inventory": raw_inventory_edge, "capture_spec": capture_edge, "build_spec": build_edge},
        "build_run_authorized": not blockers, "build_run_attempted": False,
        "report_real_number_allowed": False, "authority": "C1_RETRY_FAIL_CLOSED_MATERIALIZATION_GATE",
    }, "c1-retry-pre-run-gate", "gate_id")


def write_blocked_c1_retry_artifacts(repo_root: str | Path, gate: Mapping[str, Any]) -> dict[str, Path]:
    """Create C1 retry records only for a blocked gate; never runs a target."""

    if gate.get("status") != "C1_SINGLE_UNIT_DRY_RUN_BLOCKED":
        raise ValueError("writer only records a fail-closed blocked C1 retry")
    root = Path(repo_root).resolve(); output = root / _OUTPUT
    if output.exists():
        raise FileExistsError("C1 retry artifact root is create-only")
    output.mkdir(parents=True)
    def edge(name: str, payload: Mapping[str, Any]) -> dict[str, str]:
        return {"ref": str(_OUTPUT / name), "digest": hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}
    common = {"unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE, "report_real_number_allowed": False}
    gate_edge = edge("pre_run_gate.json", gate)
    claim = identified({"schema_version": "cipherlens.c1_retry_claim_gate.v0.1", **common, "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "pre_run_gate": gate_edge, "blocking_reasons": list(gate["blocking_reasons"]), "current_campaign_result": "NOT_GENERATED", "vulnerability_result": "NOT_GENERATED", "security_finding": False, "authority": "C1_RETRY_BLOCKED_CLAIM_GATE"}, "c1-retry-claim-gate", "decision_id")
    claim_edge = edge("claim_gate_decision.json", claim)
    raw = identified({"schema_version": "cipherlens.c1_retry_raw_artifact_manifest.v0.1", **common, "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "raw_artifacts": [], "reason_code": "PRE_RUN_GATE_BLOCKED_NO_BUILD_OR_RUN"}, "c1-retry-raw-manifest", "manifest_id")
    raw_edge = edge("raw_artifact_manifest.json", raw)
    attempt = identified({"schema_version": "cipherlens.c1_retry_attempt_manifest.v0.1", **common, "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "pre_run_gate": gate_edge, "claim_gate": claim_edge, "raw_artifact_manifest": raw_edge, "build_attempted": False, "run_attempted": False, "target_binary_started": False, "execution_verdict_generated": False, "violation_evidence_package_generated": False, "terminal_state": "PRE_RUN_GATE_BLOCKED", "blocking_reasons": list(gate["blocking_reasons"])}, "c1-retry-attempt", "attempt_id")
    attempt_edge = edge("c1_attempt_manifest.json", attempt)
    index = identified({"schema_version": "cipherlens.c1_retry_artifact_index.v0.1", **common, "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "artifacts": [{"artifact_type": k, **v} for k, v in sorted({"pre_run_gate": gate_edge, "claim_gate": claim_edge, "raw_artifact_manifest": raw_edge, "attempt_manifest": attempt_edge}.items())], "authority": "C1_RETRY_CREATE_ONLY_ARTIFACT_INDEX"}, "c1-retry-artifact-index", "index_id")
    payloads = {"pre_run_gate.json": gate, "claim_gate_decision.json": claim, "raw_artifact_manifest.json": raw, "c1_attempt_manifest.json": attempt, "artifact_index.json": index}
    for name, payload in payloads.items(): (output / name).write_bytes(canonical_json_bytes(payload))
    return {name: output / name for name in payloads}


def evaluate_c1_retry_v02_gate(repo_root: str | Path) -> dict[str, Any]:
    """Re-evaluate the fresh v0.2 attempt without invoking a compiler or runner."""
    root = Path(repo_root).resolve()
    fix8_gate, fix8_gate_edge = _read(root, str(_FIX8 / "c1_pre_run_gate_decision.json"))
    fix8_index, fix8_index_edge = _read(root, str(_FIX8 / "artifact_index.json"))
    fix7_index, fix7_index_edge = _read(root, str(_FIX7 / "artifact_index.json"))
    fix4_index, fix4_index_edge = _read(root, str(_FIX4 / "artifact_index.json"))
    provenance, provenance_edge = _read(root, str(_FIX4 / "library_build_provenance_record.json"))
    capture, capture_edge = _read(root, str(_FIX8 / "capture_region_manifest.json"))
    capture_binding, capture_binding_edge = _read(root, str(_FIX8 / "merge_capture_binding.json"))
    source_update, source_update_edge = _read(root, str(_FIX8 / "source_map_capture_update.json"))
    handoff, handoff_edge = _read(root, str(_FIX2 / "lineage/execution_handoff.json"))
    build_spec, build_spec_edge = _read(root, str(_FIX2 / "build_spec.json"))
    source_ref = str(_FIX2 / "lineage/bound_source.c")
    source_edge = _bytes_edge(root, source_ref)
    source_text = (root / source_ref).read_text()

    library_ok = all(
        (root / item["ref"]).is_file()
        and hashlib.sha256((root / item["ref"]).read_bytes()).hexdigest() == item["digest"]
        for item in provenance.get("generated_library_artifacts", [])
    )
    handoff_ok = (
        build_spec.get("execution_handoff_ref") == handoff.get("handoff_id")
        and build_spec.get("execution_handoff_digest") == artifact_digest(handoff)
        and build_spec.get("source_artifact_ref") == source_ref
        and build_spec.get("source_artifact_digest") == source_edge["digest"]
    )
    regions = capture.get("capture_regions", [])
    declared_capture_ok = (
        len(regions) == 1
        and regions[0].get("capture_region_id") == "region:c1-overlay:oracle-event-capture"
        and regions[0].get("protected") is False
        and capture_binding.get("status") == "READY"
        and source_update.get("status") == "READY"
    )
    no_masks = _MASK.search(source_text) is None
    capture_materialized = (
        "emit_runtime_event_v0_1" in source_text
        or "RUNTIME_EVENT_V0_1" in source_text
    )
    checks = [
        _check("APPROVED_UNIT", fix8_gate.get("unit_id") == APPROVED_UNIT_ID, "APPROVED_TRACK_A_0020_FIXED_UNIT_VERIFIED", fix8_gate_edge),
        _check("C1_FIX8_GATE", fix8_gate.get("status") == "C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" and not fix8_gate.get("blocking_reasons"), "C1_FIX8_LINEAGE_VERIFIED", fix8_index_edge),
        _check("FIXED_LIBRARY_PROVENANCE", provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY" and library_ok, "REPRODUCIBLE_PROVENANCE_READY", provenance_edge),
        _check("DECLARED_CAPTURE_REGION", declared_capture_ok, "DECLARED_CAPTURE_REGION_LINEAGE_VERIFIED", capture_edge),
        _check("RUNTIME_EVENT_LINEAGE", fix7_index.get("schema_version") == "cipherlens.c1_fix7_artifact_index.v0.1", "RUNTIME_EVENT_LINEAGE_VERIFIED", fix7_index_edge),
        _check("EXECUTION_HANDOFF", handoff_ok, "EXECUTION_HANDOFF_DIGEST_MISMATCH", handoff_edge),
        _check("BUILDSPEC", build_spec.get("schema_version") == "cipherlens.build_spec.v0.1" and handoff_ok, "BUILDSPEC_LINEAGE_INVALID", build_spec_edge),
        _check("BOUND_SOURCE_VALUES", no_masks, "BOUND_SOURCE_TEMPLATE_VALUES_UNRESOLVED", source_edge),
        _check("CAPTURE_REGION_MATERIALIZATION", capture_materialized, "DECLARED_CAPTURE_REGION_NOT_MATERIALIZED_IN_BOUND_SOURCE", source_update_edge),
        _check("RUNSPEC_ADAPTER", (root / "execution_pipeline/runner_adapter.py").is_file(), "RUNSPEC_ADAPTER_UNAVAILABLE"),
    ]
    blockers = [item["reason_code"] for item in checks if item["status"] != "PASS"]
    return identified({
        "schema_version": "cipherlens.c1_retry_pre_run_gate.v0.2",
        "attempt_version": "v0.2",
        "unit_id": APPROVED_UNIT_ID,
        "scope": "SINGLE_UNIT_DRY_RUN",
        "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_PRE_RUN_GATE_PASSED" if not blockers else "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "checks": checks,
        "blocking_reasons": blockers,
        "parent_lineage": {
            "c1_fix8": fix8_index_edge,
            "runtime_event_lineage": fix7_index_edge,
            "fixed_library_provenance": fix4_index_edge,
        },
        "input_artifacts": {
            "fixed_library_provenance": provenance_edge,
            "capture_region": capture_edge,
            "capture_binding": capture_binding_edge,
            "source_map_capture_update": source_update_edge,
            "execution_handoff": handoff_edge,
            "build_spec": build_spec_edge,
            "bound_source": source_edge,
        },
        "build_run_authorized": not blockers,
        "build_attempted": False,
        "run_attempted": False,
        "report_real_number_allowed": False,
        "authority": "C1_RETRY_V02_FAIL_CLOSED_MATERIALIZATION_GATE",
    }, "c1-retry-v02-pre-run-gate", "gate_id")


def c1_retry_v02_blocked_documents(gate: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if gate.get("status") != "C1_SINGLE_UNIT_DRY_RUN_BLOCKED":
        raise ValueError("blocked v0.2 documents require a blocked pre-run gate")
    common = {
        "attempt_version": "v0.2",
        "unit_id": APPROVED_UNIT_ID,
        "scope": "SINGLE_UNIT_DRY_RUN",
        "campaign_scope": CAMPAIGN_SCOPE,
        "report_real_number_allowed": False,
        "parent_lineage": dict(gate["parent_lineage"]),
    }
    def edge(name: str, payload: Mapping[str, Any]) -> dict[str, str]:
        return {"ref": str(_OUTPUT_V02 / name), "digest": hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}
    gate_edge = edge("pre_run_gate.json", gate)
    claim = identified({
        "schema_version": "cipherlens.c1_retry_claim_gate.v0.2",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "pre_run_gate": gate_edge,
        "blocking_reasons": list(gate["blocking_reasons"]),
        "allowed_claims": ["ENGINEERING_BLOCKER_CLAIM"],
        "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "authority": "C1_RETRY_V02_BLOCKED_CLAIM_GATE",
    }, "c1-retry-v02-claim-gate", "decision_id")
    claim_edge = edge("claim_gate.json", claim)
    attempt = identified({
        "schema_version": "cipherlens.c1_retry_attempt_manifest.v0.2",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "pre_run_gate": gate_edge,
        "claim_gate": claim_edge,
        "terminal_state": "PRE_RUN_GATE_BLOCKED",
        "blocking_reasons": list(gate["blocking_reasons"]),
        "build_attempted": False,
        "run_attempted": False,
        "target_binary_started": False,
        "runtime_event_generated": False,
        "witness_generated": False,
        "trace_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
    }, "c1-retry-v02-attempt", "attempt_id")
    attempt_edge = edge("attempt_manifest.json", attempt)
    documents = {
        "pre_run_gate.json": dict(gate),
        "claim_gate.json": claim,
        "attempt_manifest.json": attempt,
    }
    index = identified({
        "schema_version": "cipherlens.c1_retry_artifact_index.v0.2",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "artifacts": [
            {"artifact_type": name[:-5], **edge(name, payload)}
            for name, payload in sorted(documents.items())
        ],
        "create_only": True,
        "authority": "C1_RETRY_V02_CREATE_ONLY_ARTIFACT_INDEX",
    }, "c1-retry-v02-artifact-index", "index_id")
    documents["artifact_index.json"] = index
    return documents


def write_c1_retry_v02_blocked_artifacts(repo_root: str | Path, gate: Mapping[str, Any]) -> dict[str, Path]:
    root = Path(repo_root).resolve()
    output = root / _OUTPUT_V02
    if output.exists():
        raise FileExistsError("C1 retry v0.2 artifact root is create-only")
    documents = c1_retry_v02_blocked_documents(gate)
    output.mkdir(parents=True)
    for name, payload in documents.items():
        (output / name).write_bytes(canonical_json_bytes(payload))
    return {name: output / name for name in documents}


def _edge_valid(root: Path, edge: Mapping[str, Any]) -> bool:
    ref = edge.get("ref")
    digest = edge.get("digest")
    if not isinstance(ref, str) or not isinstance(digest, str):
        return False
    path = root / ref
    return path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest


def evaluate_c1_retry_v03_gate(repo_root: str | Path) -> dict[str, Any]:
    """Evaluate execution materializability without compiling or running.

    C1-fix9 deliberately produced a canonical target-specific specification,
    not executable source.  This gate refuses to reuse the older C0 source or
    to invent capture code outside the declared capture-region lineage.
    """

    root = Path(repo_root).resolve()
    fix9_gate, fix9_gate_edge = _read(root, str(_FIX9 / "c1_pre_run_gate_decision.json"))
    fix9_index, fix9_index_edge = _read(root, str(_FIX9 / "artifact_index.json"))
    bound_source, bound_source_edge = _read(root, str(_FIX9 / "bound_source_materialization.json"))
    final_map, final_map_edge = _read(root, str(_FIX9 / "source_map_finalization.json"))
    handoff, handoff_edge = _read(root, str(_FIX9 / "execution_handoff_readiness.json"))
    captures, captures_edge = _read(root, str(_FIX9 / "capture_binding_materialization.json"))
    fix8_index, fix8_index_edge = _read(root, str(_FIX8 / "artifact_index.json"))
    fix7_index, fix7_index_edge = _read(root, str(_FIX7 / "artifact_index.json"))
    fix4_index, fix4_index_edge = _read(root, str(_FIX4 / "artifact_index.json"))
    provenance, provenance_edge = _read(root, str(_FIX4 / "library_build_provenance_record.json"))

    roles = {item.get("semantic_role") for item in captures.get("capture_bindings", [])}
    emitter_edges = [
        {"ref": item.get("emitter_ref"), "digest": item.get("emitter_digest")}
        for item in captures.get("capture_bindings", [])
    ]
    source_edge = bound_source.get("base_source_artifact", {})
    source_text = ""
    if _edge_valid(root, source_edge):
        source_text = (root / source_edge["ref"]).read_text(encoding="utf-8")
    libraries_ready = bool(provenance.get("generated_library_artifacts")) and all(
        _edge_valid(root, item)
        for item in provenance.get("generated_library_artifacts", [])
    )
    handoff_edges = [
        handoff.get("bound_source", {}),
        handoff.get("source_map", {}),
        handoff.get("candidate_binding_artifact", {}),
        handoff.get("merge_artifact", {}),
        handoff.get("build_profile", {}),
    ]
    handoff_valid = (
        handoff.get("status") == "READY"
        and handoff.get("claim_boundary", {}).get("allowed_next_stage") == "C1_RETRY_ONLY"
        and all(_edge_valid(root, edge) for edge in handoff_edges)
    )
    source_executable = (
        bound_source.get("status") == "READY"
        and bound_source.get("executable_source_generated") is True
        and bound_source.get("source_generation_mode") == "DETERMINISTIC_DECLARED_REGION_RENDER"
        and _edge_valid(root, source_edge)
        and _MASK.search(source_text) is None
    )
    capture_protocol_materialized = (
        source_executable
        and "ORACLE_EVENT_V0_1" in source_text
        and roles == {"operation_outcome", "consumed_length", "input_length"}
    )
    build_spec_materializable = source_executable and libraries_ready and handoff_valid
    run_spec_materializable = (
        build_spec_materializable
        and capture_protocol_materialized
        and (root / "execution_pipeline/runner_adapter.py").is_file()
    )

    checks = [
        _check(
            "BOUND_SOURCE_READINESS",
            bound_source.get("status") == "READY"
            and bound_source.get("schema_version") == "cipherlens.materialized_bound_source.v0.1",
            "BOUND_SOURCE_READINESS_NOT_READY",
            bound_source_edge,
        ),
        _check(
            "SOURCE_MAP_CAPTURE_REGION",
            final_map.get("status") == "READY"
            and roles == {"operation_outcome", "consumed_length", "input_length"},
            "SOURCE_MAP_CAPTURE_REGION_NOT_READY",
            final_map_edge,
        ),
        _check(
            "RUNTIME_EVENT_EMITTER",
            bool(emitter_edges) and all(_edge_valid(root, edge) for edge in emitter_edges),
            "RUNTIME_EVENT_EMITTER_NOT_READY",
            captures_edge,
        ),
        _check(
            "BUILD_ENVIRONMENT_PROVENANCE",
            provenance.get("validation_status") == "REPRODUCIBLE_PROVENANCE_READY"
            and libraries_ready,
            "BUILD_ENVIRONMENT_PROVENANCE_INCOMPLETE",
            provenance_edge,
        ),
        _check(
            "EXECUTION_HANDOFF",
            handoff_valid,
            "EXECUTION_HANDOFF_DIGEST_INVALID",
            handoff_edge,
        ),
        _check(
            "BUILDSPEC_MATERIALIZABLE",
            build_spec_materializable,
            "EXECUTABLE_BOUND_SOURCE_NOT_MATERIALIZED",
            bound_source_edge,
        ),
        _check(
            "RUNSPEC_MATERIALIZABLE",
            run_spec_materializable,
            "DECLARED_CAPTURE_PROTOCOL_NOT_MATERIALIZED",
            captures_edge,
        ),
    ]
    blockers = [item["reason_code"] for item in checks if item["status"] != "PASS"]
    return identified({
        "schema_version": "cipherlens.c1_retry_pre_run_gate.v0.3",
        "attempt_version": "v0.3",
        "unit_id": APPROVED_UNIT_ID,
        "scope": "SINGLE_UNIT_DRY_RUN",
        "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_PRE_RUN_GATE_PASSED" if not blockers else "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "checks": checks,
        "blocking_reasons": blockers,
        "parent_lineage": {
            "c1_fix9": fix9_index_edge,
            "c1_fix8": fix8_index_edge,
            "c1_fix7": fix7_index_edge,
            "c1_fix4": fix4_index_edge,
        },
        "input_artifacts": {
            "c1_fix9_gate": fix9_gate_edge,
            "bound_source_materialization": bound_source_edge,
            "source_map_finalization": final_map_edge,
            "execution_handoff_readiness": handoff_edge,
            "capture_binding_materialization": captures_edge,
            "library_build_provenance": provenance_edge,
        },
        "fix9_gate_status": fix9_gate.get("status"),
        "fix9_index_status": fix9_index.get("status"),
        "fix8_index_status": fix8_index.get("status"),
        "fix7_index_status": fix7_index.get("status"),
        "fix4_index_status": fix4_index.get("status"),
        "source_materialization": {
            "kind": bound_source.get("materialization_kind"),
            "source_generation_mode": bound_source.get("source_generation_mode"),
            "executable_source_generated": bound_source.get("executable_source_generated"),
            "unresolved_template_masks_present": bool(_MASK.search(source_text)),
            "declared_capture_protocol_present": "ORACLE_EVENT_V0_1" in source_text,
            "older_c0_source_reuse_allowed": False,
        },
        "build_authorized": not blockers,
        "build_attempted": False,
        "run_authorized": not blockers,
        "run_attempted": False,
        "runtime_event_generated": False,
        "witness_generated": False,
        "trace_generated": False,
        "projection_generated": False,
        "relation_evaluation_generated": False,
        "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "report_real_number_allowed": False,
        "authority": "C1_RETRY_V03_FAIL_CLOSED_EXECUTION_MATERIALIZATION_GATE",
    }, "c1-retry-v03-pre-run-gate", "gate_id")


def c1_retry_v03_blocked_documents(gate: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if gate.get("status") != "C1_SINGLE_UNIT_DRY_RUN_BLOCKED":
        raise ValueError("blocked v0.3 documents require a blocked pre-run gate")
    common = {
        "attempt_version": "v0.3",
        "unit_id": APPROVED_UNIT_ID,
        "scope": "SINGLE_UNIT_DRY_RUN",
        "campaign_scope": CAMPAIGN_SCOPE,
        "report_real_number_allowed": False,
        "parent_lineage": dict(gate["parent_lineage"]),
    }

    def edge(name: str, payload: Mapping[str, Any]) -> dict[str, str]:
        return {
            "ref": str(_OUTPUT_V03 / name),
            "digest": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
        }

    gate_edge = edge("pre_run_gate.json", gate)
    claim = identified({
        "schema_version": "cipherlens.c1_retry_claim_gate.v0.3",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "pre_run_gate": gate_edge,
        "blocking_reasons": list(gate["blocking_reasons"]),
        "allowed_claims": ["ENGINEERING_BLOCKER_CLAIM"],
        "forbidden_claims": [
            "CURRENT_V2_CAMPAIGN_RESULT",
            "SECURITY_FINDING",
            "VULNERABILITY_CONFIRMED",
            "LIBRARY_SAFE",
        ],
        "current_campaign_result": "NOT_GENERATED",
        "security_finding": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED",
        "execution_verdict": "NOT_GENERATED",
        "authority": "C1_RETRY_V03_BLOCKED_CLAIM_GATE",
    }, "c1-retry-v03-claim-gate", "decision_id")
    claim_edge = edge("claim_gate.json", claim)
    attempt = identified({
        "schema_version": "cipherlens.c1_retry_attempt_manifest.v0.3",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "pre_run_gate": gate_edge,
        "claim_gate": claim_edge,
        "terminal_state": "PRE_RUN_GATE_BLOCKED",
        "blocking_reasons": list(gate["blocking_reasons"]),
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
    }, "c1-retry-v03-attempt", "attempt_id")
    documents = {
        "pre_run_gate.json": dict(gate),
        "claim_gate.json": claim,
        "attempt_manifest.json": attempt,
    }
    index = identified({
        "schema_version": "cipherlens.c1_retry_artifact_index.v0.3",
        **common,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED",
        "artifacts": [
            {"artifact_type": name[:-5], **edge(name, payload)}
            for name, payload in sorted(documents.items())
        ],
        "create_only": True,
        "authority": "C1_RETRY_V03_CREATE_ONLY_ARTIFACT_INDEX",
    }, "c1-retry-v03-artifact-index", "index_id")
    documents["artifact_index.json"] = index
    return documents


def write_c1_retry_v03_blocked_artifacts(
    repo_root: str | Path,
    gate: Mapping[str, Any],
) -> dict[str, Path]:
    root = Path(repo_root).resolve()
    output = root / _OUTPUT_V03
    if output.exists():
        raise FileExistsError("C1 retry v0.3 artifact root is create-only")
    documents = c1_retry_v03_blocked_documents(gate)
    output.mkdir(parents=True)
    for name, payload in documents.items():
        (output / name).write_bytes(canonical_json_bytes(payload))
    return {name: output / name for name in documents}
