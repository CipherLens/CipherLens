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

from target_knowledge.canonical import canonical_json_bytes, identified

from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE, SCOPE


_FIX2 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1")
_FIX4 = Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1")
_OUTPUT = Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1")
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
