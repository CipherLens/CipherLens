"""Fail-closed C1 gate for the sole approved single-unit dry run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes, identified


APPROVED_UNIT_ID = "unit:track-a:0020:fixed"
SCOPE = "SINGLE_UNIT_DRY_RUN"
CAMPAIGN_SCOPE = "NOT_FULL_CAMPAIGN"
PREPARATION_ROOT = Path("artifacts/pipeline_v2/real_campaign_preflight")


def _read_json(repo_root: Path, relative_ref: str) -> tuple[dict[str, Any], str]:
    path = repo_root / relative_ref
    payload = path.read_bytes()
    return json.loads(payload), hashlib.sha256(payload).hexdigest()


def _digest_file(repo_root: Path, relative_ref: str) -> str:
    return hashlib.sha256((repo_root / relative_ref).read_bytes()).hexdigest()


def _check(name: str, passed: bool, reason: str, refs: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {"check": name, "status": "PASS" if passed else "BLOCKED", "reason_code": reason, "evidence_refs": refs or []}


def evaluate_c1_pre_run_gate(repo_root: Path) -> dict[str, Any]:
    """Audit C1 prerequisites without invoking any compiler, binary, or runner."""

    repo_root = repo_root.resolve()
    population_ref = str(PREPARATION_ROOT / "population_manifests/CLV2-RQ4-PILOT-001.json")
    population, population_digest = _read_json(repo_root, population_ref)
    units = [item for item in population.get("units", []) if item.get("unit_id") == APPROVED_UNIT_ID]
    unit = units[0] if len(units) == 1 else {}
    checks = [
        _check("FROZEN_POPULATION", len(population.get("units", [])) == 11, "FROZEN_11_UNIT_POPULATION_VERIFIED", [{"ref": population_ref, "digest": population_digest}]),
        _check("APPROVED_UNIT", len(units) == 1 and unit.get("track") == "A", "APPROVED_TRACK_A_0020_FIXED_UNIT_VERIFIED"),
    ]
    if not unit:
        return _gate_document(checks, population_ref, population_digest, {})

    profile_ref = str(PREPARATION_ROOT / unit["build_profile_ref"])
    pair_ref = str(PREPARATION_ROOT / unit["source_pair_ref"])
    profile, profile_digest = _read_json(repo_root, profile_ref)
    pair, pair_digest = _read_json(repo_root, pair_ref)
    source_ref = str(PREPARATION_ROOT / profile["source_root"]["ref"])
    source, source_digest = _read_json(repo_root, source_ref)
    contract_ref = unit["source_contract_ref"]
    contract_digest = _digest_file(repo_root, contract_ref)
    signature_ref = pair["transfer_signature_ref"]
    signature_digest = _digest_file(repo_root, signature_ref)
    template_ref = pair["template_ref"]
    template_payload = (repo_root / template_ref).read_bytes()
    template_digest = hashlib.sha256(template_payload).hexdigest()
    capture_ref = str(PREPARATION_ROOT / "capture_bridge/readiness_7d_b.json")
    capture, capture_digest = _read_json(repo_root, capture_ref)
    include_ref = str(PREPARATION_ROOT / profile["include_path_evidence"][0]["ref"])
    include_evidence, include_digest = _read_json(repo_root, include_ref)
    c0_lineage_ref = "artifacts/pipeline_v2/c0_replay/replay_lineages/0020.fixed.json"
    c0_lineage, c0_lineage_digest = _read_json(repo_root, c0_lineage_ref)

    checks.extend([
        _check("SOURCE_IDENTITY", source_digest == profile["source_root"]["digest"] and source.get("identity", {}).get("revision") == "a7f651cf160a3753367e032c4471699822b37e30", "FIXED_SOURCE_IDENTITY_DIGEST_VERIFIED", [{"ref": source_ref, "digest": source_digest}]),
        _check("BUILD_PROFILE", profile_digest == unit["build_profile_digest"], "FIXED_BUILD_PROFILE_DIGEST_VERIFIED", [{"ref": profile_ref, "digest": profile_digest}]),
        _check("DIFFERENTIAL_PAIR", pair_digest == unit["source_pair_digest"] and pair.get("fixed_profile_digest") == profile_digest, "0020_DIFFERENTIAL_PAIR_DIGEST_VERIFIED", [{"ref": pair_ref, "digest": pair_digest}]),
        _check("CONTRACT", contract_digest == unit["source_contract_digest"], "CONTRACT_DIGEST_VERIFIED", [{"ref": contract_ref, "digest": contract_digest}]),
        _check("TRANSFER_SIGNATURE", signature_digest == pair["transfer_signature_digest"], "TRANSFER_SIGNATURE_DIGEST_VERIFIED", [{"ref": signature_ref, "digest": signature_digest}]),
        _check("TRIGGER_TEMPLATE", template_digest == pair["template_digest"], "TRIGGER_TEMPLATE_DIGEST_VERIFIED", [{"ref": template_ref, "digest": template_digest}]),
        _check("CAPTURE_SPEC", set(capture.get("cases", {}).get("0020", {}).get("required_roles", [])) == {"operation_outcome", "consumed_length", "input_length"} and capture.get("cases", {}).get("0020", {}).get("correlation_requirement") == "shared operation/input correlation group", "0020_CAPTURE_ROLES_AND_CORRELATION_VERIFIED", [{"ref": capture_ref, "digest": capture_digest}]),
        _check("REPRODUCIBLE_TARGET_LIBRARY", bool(profile.get("library_inputs")) and not profile.get("missing_artifacts"), "REPRODUCIBLE_TARGET_LIBRARY_MISSING"),
        _check("FIXED_INCLUDE_EVIDENCE", include_evidence.get("source_identity_ref") == "source_identities/mbedtls-0020-fixed.json" and include_evidence.get("source_identity_digest") == source_digest, "FIXED_INCLUDE_EVIDENCE_POINTS_TO_BUGGY_SOURCE", [{"ref": include_ref, "digest": include_digest}]),
        _check("LOCAL_SOURCE_RESOLUTION", bool((profile.get("telemetry") or {}).get("source_root")), "FIXED_SOURCE_ROOT_HAS_NO_LOCAL_EXECUTION_MAPPING"),
        _check("CANONICAL_C1_LINEAGE", c0_lineage.get("classification") != "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN", "ONLY_C0_REPLAY_FIXTURE_LINEAGE_AVAILABLE", [{"ref": c0_lineage_ref, "digest": c0_lineage_digest}]),
        _check("BUILDSPEC_RUNSPEC_ELIGIBILITY", bool(profile.get("library_inputs")) and not profile.get("missing_artifacts") and c0_lineage.get("classification") != "C0_REPLAY_FIXTURE_NOT_REAL_CAMPAIGN", "CANONICAL_C1_BUILDSPEC_RUNSPEC_NOT_MATERIALIZABLE"),
    ])
    inputs = {
        "population": {"ref": population_ref, "digest": population_digest},
        "source_identity": {"ref": source_ref, "digest": source_digest},
        "build_profile": {"ref": profile_ref, "digest": profile_digest},
        "differential_pair": {"ref": pair_ref, "digest": pair_digest},
        "contract": {"ref": contract_ref, "digest": contract_digest},
        "transfer_signature": {"ref": signature_ref, "digest": signature_digest},
        "trigger_template": {"ref": template_ref, "digest": template_digest},
        "capture_spec": {"ref": capture_ref, "digest": capture_digest},
        "c0_replay_lineage": {"ref": c0_lineage_ref, "digest": c0_lineage_digest},
    }
    return _gate_document(checks, population_ref, population_digest, inputs)


def _gate_document(checks: list[dict[str, Any]], population_ref: str, population_digest: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    blockers = [item["reason_code"] for item in checks if item["status"] != "PASS"]
    return identified({
        "schema_version": "cipherlens.c1_single_unit_pre_run_gate.v0.1",
        "unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED" if blockers else "C1_PRE_RUN_GATE_PASSED",
        "checks": checks, "blocking_reasons": blockers, "input_artifacts": dict(inputs),
        "population_manifest_ref": population_ref, "population_manifest_digest": population_digest,
        "build_run_authorized": not blockers, "build_run_attempted": False,
        "report_real_number_allowed": False, "execution_verdict_generated": False,
        "violation_evidence_package_generated": False,
        "authority": "C1_PRE_RUN_GATE_ONLY",
    }, "c1-pre-run-gate", "gate_id")


def make_c1_blocked_claim_gate(pre_run_gate: Mapping[str, Any], *, gate_ref: str, gate_digest: str) -> dict[str, Any]:
    if pre_run_gate.get("status") != "C1_SINGLE_UNIT_DRY_RUN_BLOCKED":
        raise ValueError("blocked C1 claim gate requires blocked pre-run gate")
    return identified({
        "schema_version": "cipherlens.c1_single_unit_claim_gate.v0.1",
        "unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "pre_run_gate_ref": gate_ref,
        "pre_run_gate_digest": gate_digest, "blocking_reasons": list(pre_run_gate["blocking_reasons"]),
        "real_execution_completed": False, "current_campaign_result": "NOT_GENERATED",
        "vulnerability_result": "NOT_GENERATED", "report_real_number_allowed": False,
        "allowed_claim_levels": ["ENGINEERING_BLOCKER_CLAIM"],
        "forbidden_claim_levels": ["CURRENT_CAMPAIGN_RESULT_CLAIM", "SECURITY_FINDING_CLAIM", "UPSTREAM_CONFIRMED_CLAIM", "LIBRARY_SAFE_CLAIM"],
        "authority": "C1_BLOCKED_NO_EXECUTION_CLAIM_GATE",
    }, "c1-claim-gate", "decision_id")


def make_c1_blocked_manifests(pre_run_gate: Mapping[str, Any], claim_gate: Mapping[str, Any], *, gate_edge: Mapping[str, str], claim_edge: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    common = {
        "unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "report_real_number_allowed": False,
    }
    raw = identified({
        "schema_version": "cipherlens.c1_raw_artifact_manifest.v0.1", **common,
        "raw_artifacts": [], "reason_code": "PRE_RUN_GATE_BLOCKED_NO_PROCESS_STARTED",
    }, "c1-raw-manifest", "manifest_id")
    raw_edge = {
        "ref": "raw_artifacts/manifest.json",
        "digest": hashlib.sha256(canonical_json_bytes(raw)).hexdigest(),
    }
    attempt = identified({
        "schema_version": "cipherlens.c1_attempt_manifest.v0.1", **common,
        "pre_run_gate": dict(gate_edge), "claim_gate": dict(claim_edge),
        "raw_artifact_manifest": raw_edge,
        "build_attempted": False, "run_attempted": False, "target_binary_started": False,
        "execution_verdict_generated": False, "violation_evidence_package_generated": False,
        "blocking_reasons": list(pre_run_gate["blocking_reasons"]),
        "terminal_state": "PRE_RUN_GATE_BLOCKED",
    }, "c1-attempt", "attempt_id")
    reproduction = identified({
        "schema_version": "cipherlens.c1_reproduction_readiness.v0.1", **common,
        "pre_run_gate": dict(gate_edge), "claim_gate": dict(claim_edge),
        "raw_artifact_manifest": raw_edge,
        "input_artifacts": dict(pre_run_gate.get("input_artifacts", {})),
        "reproduction_command": "NOT_AVAILABLE_PRE_RUN_GATE_BLOCKED",
        "next_required_artifacts": ["resolved_fixed_source_root", "digest_addressed_reproducible_target_library", "fixed_source_include_evidence", "c1_candidate_binding_merge_bound_source_handoff"],
    }, "c1-reproduction", "manifest_id")
    return attempt, raw, reproduction


def make_c1_artifact_index(artifacts: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    required = {"pre_run_gate", "claim_gate", "attempt_manifest", "raw_artifact_manifest", "reproduction_readiness"}
    if set(artifacts) != required:
        raise ValueError("C1 artifact index requires the complete blocked artifact set")
    entries = []
    for name in sorted(artifacts):
        edge = artifacts[name]
        digest = edge.get("digest", "")
        if not edge.get("ref") or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError(f"invalid C1 artifact edge: {name}")
        entries.append({"artifact_type": name, "ref": edge["ref"], "digest": digest})
    return identified({
        "schema_version": "cipherlens.c1_artifact_index.v0.1",
        "unit_id": APPROVED_UNIT_ID, "scope": SCOPE, "campaign_scope": CAMPAIGN_SCOPE,
        "status": "C1_SINGLE_UNIT_DRY_RUN_BLOCKED", "artifacts": entries,
        "report_real_number_allowed": False, "authority": "C1_CREATE_ONLY_ARTIFACT_INDEX",
    }, "c1-artifact-index", "index_id")
