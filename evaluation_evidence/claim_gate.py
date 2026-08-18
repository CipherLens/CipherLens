"""Deterministic report/PPT claim gate with no NLP or security inference."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable, Mapping

from evaluation_evidence.canonical import canonical_json_bytes, identify
from evaluation_evidence.findings import finding_link
from evaluation_evidence.lineage import validate_link
from evaluation_evidence.model import (
    ClaimGateResult, ClaimTaxonomy, EvidenceOrigin, FindingStatus,
    REGISTRY_VERSION, RecomputeStatus, SCHEMA_VERSIONS, ValidationMaturity,
)
from evaluation_evidence.registry import validate_document_or_raise


def build_claim_record(
    *, claim_taxonomy: ClaimTaxonomy | str, statement: str, scope: Mapping[str, bool],
    evidence_refs: Iterable[Mapping[str, str]] = (), metric_refs: Iterable[Mapping[str, str]] = (),
    finding_refs: Iterable[Mapping[str, str]] = (), requested_report_sections: Iterable[str] = (),
    requested_ppt_usage: Iterable[str] = (), public_disclosure_state: str = "LOCAL_ONLY",
    git_revision: str, producer_id: str = "claim-record-builder", producer_version: str = "0.1",
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSIONS["claim_record"], "claim_id": "pending",
        "claim_taxonomy": claim_taxonomy.value if isinstance(claim_taxonomy, ClaimTaxonomy) else claim_taxonomy,
        "statement": statement, "scope": dict(scope),
        "evidence_refs": [dict(item) for item in evidence_refs],
        "metric_refs": [dict(item) for item in metric_refs],
        "finding_refs": [dict(item) for item in finding_refs],
        "requested_report_sections": list(requested_report_sections),
        "requested_ppt_usage": list(requested_ppt_usage),
        "public_disclosure_state": public_disclosure_state,
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "git_revision": git_revision,
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result


def claim_link(claim: Mapping[str, Any]) -> dict[str, str]:
    validate_document_or_raise(claim)
    return {
        "ref": f"claim:{claim['claim_id']}",
        "digest": hashlib.sha256(canonical_json_bytes(claim)).hexdigest(),
    }


def metric_link(record: Mapping[str, Any]) -> dict[str, str]:
    validate_document_or_raise(record)
    return {
        "ref": f"metric-record:{record['metric_record_id']}",
        "digest": hashlib.sha256(canonical_json_bytes(record)).hexdigest(),
    }


def _links_equal(left: Mapping[str, str], right: Mapping[str, str]) -> bool:
    return left.get("ref") == right.get("ref") and left.get("digest") == right.get("digest")


def evaluate_claim(
    claim: Mapping[str, Any], *, artifact_records: Iterable[Mapping[str, Any]],
    metric_records: Iterable[Mapping[str, Any]] = (), findings: Iterable[Mapping[str, Any]] = (),
    resolver: Callable[[str, str], bool],
    producer_id: str = "deterministic-claim-gate", producer_version: str = "0.1",
) -> dict[str, Any]:
    validate_document_or_raise(claim)
    artifacts = list(artifact_records)
    metrics = list(metric_records)
    finding_values = list(findings)
    for record in artifacts + metrics:
        validate_document_or_raise(record)
    artifact_index = {
        (record.get("artifact_ref"), record.get("artifact_digest")): record
        for record in artifacts if record.get("artifact_digest") is not None
    }
    metric_index = {(link["ref"], link["digest"]): record for record in metrics for link in [metric_link(record)]}
    finding_index = {(link["ref"], link["digest"]): record for record in finding_values for link in [finding_link(record)]}
    reason_codes: list[str] = []
    blocking_refs: list[dict[str, str]] = []
    resolved_artifacts: list[Mapping[str, Any]] = []
    resolved_metrics: list[Mapping[str, Any]] = []
    resolved_findings: list[Mapping[str, Any]] = []

    all_requested = list(claim["evidence_refs"]) + list(claim["metric_refs"]) + list(claim["finding_refs"])
    if not all_requested:
        reason_codes.append("NO_ARTIFACT_OR_PROVENANCE")
    for link in all_requested:
        if validate_link(link) or not resolver(str(link["ref"]), str(link["digest"])):
            reason_codes.append("ARTIFACT_MISSING_OR_DIGEST_INVALID")
            blocking_refs.append(dict(link))
    for link in claim["evidence_refs"]:
        record = artifact_index.get((link["ref"], link["digest"]))
        if record is None:
            reason_codes.append("ARTIFACT_RECORD_MISSING")
            blocking_refs.append(dict(link))
        else:
            resolved_artifacts.append(record)
    for link in claim["metric_refs"]:
        record = metric_index.get((link["ref"], link["digest"]))
        if record is None:
            reason_codes.append("METRIC_RECORD_MISSING")
            blocking_refs.append(dict(link))
        else:
            resolved_metrics.append(record)
    for link in claim["finding_refs"]:
        record = finding_index.get((link["ref"], link["digest"]))
        if record is None:
            reason_codes.append("FINDING_RECORD_MISSING")
            blocking_refs.append(dict(link))
        else:
            resolved_findings.append(record)

    hard_block = bool(reason_codes)
    scope = claim["scope"]
    taxonomy = claim["claim_taxonomy"]
    if scope["current_v2"] and (
        any(record["origin"] != EvidenceOrigin.CURRENT_V2.value for record in resolved_artifacts)
        or any(record["origin"] != EvidenceOrigin.CURRENT_V2.value for record in resolved_metrics)
        or any(record["origin"] != EvidenceOrigin.CURRENT_V2.value for record in resolved_findings)
    ):
        reason_codes.append("LEGACY_OR_NON_V2_MASQUERADES_AS_CURRENT_V2")
        hard_block = True
    if scope["global_security"]:
        reason_codes.append("WITNESS_CANNOT_PROVE_GLOBAL_LIBRARY_SECURITY")
        hard_block = True
    if scope["confirmed_vulnerability"]:
        allowed = {FindingStatus.CVE_OR_ADVISORY_CONFIRMED.value}
        if not resolved_findings or any(item["finding_status"] not in allowed for item in resolved_findings):
            reason_codes.append("VIOLATED_OR_RELATION_BEHAVIOR_IS_NOT_CONFIRMED_VULNERABILITY")
            hard_block = True
    if claim["requested_ppt_usage"] and claim["public_disclosure_state"] in {"EMBARGOED", "PRIVATE"}:
        reason_codes.append("PUBLIC_DISCLOSURE_POLICY_BLOCKS_PPT")
        hard_block = True

    result = ClaimGateResult.ALLOW
    if hard_block:
        result = ClaimGateResult.BLOCK
    elif taxonomy == ClaimTaxonomy.CURRENT_CAMPAIGN_RESULT_CLAIM.value:
        real_execution = any(
            record["origin"] == EvidenceOrigin.CURRENT_V2.value
            and record["synthetic_or_real"] == "REAL"
            and ValidationMaturity.DIGEST_VERIFIED.value in record["validation_maturity"]
            and ValidationMaturity.SCHEMA_VALIDATED.value in record["validation_maturity"]
            and ValidationMaturity.REAL_EXECUTION_REPRODUCED.value in record["validation_maturity"]
            and record["artifact_type"] in {"campaign_attempt", "execution_witness", "execution_verdict", "violation_package"}
            for record in resolved_artifacts
        )
        if not real_execution:
            result = ClaimGateResult.NEEDS_RERUN
            reason_codes.append("CURRENT_V2_REAL_EXECUTION_ARTIFACT_REQUIRED")
    if result == ClaimGateResult.ALLOW and any(
        record["recompute_status"] != RecomputeStatus.RECOMPUTABLE.value
        or not record["population_complete"] or not record["all_source_digests_valid"]
        for record in resolved_metrics
    ):
        result = ClaimGateResult.NEEDS_RECOMPUTATION
        reason_codes.append("METRIC_PROVENANCE_NOT_RECOMPUTABLE")
    if result == ClaimGateResult.ALLOW and (
        taxonomy == ClaimTaxonomy.UPSTREAM_CONFIRMED_CLAIM.value or scope["upstream_acknowledged"]
    ):
        acknowledged = any(
            finding["finding_status"] in {
                FindingStatus.UPSTREAM_ACKNOWLEDGED.value,
                FindingStatus.FIX_CONFIRMED.value,
                FindingStatus.CVE_OR_ADVISORY_CONFIRMED.value,
            }
            and finding["upstream_refs"]
            for finding in resolved_findings
        )
        external = any(record["origin"] == EvidenceOrigin.EXTERNAL_UPSTREAM.value for record in resolved_artifacts)
        if not acknowledged or not external:
            result = ClaimGateResult.NEEDS_EXTERNAL_CONFIRMATION
            reason_codes.append("AUTHORITATIVE_EXTERNAL_UPSTREAM_EVIDENCE_REQUIRED")
    if result == ClaimGateResult.ALLOW and taxonomy == ClaimTaxonomy.LEGACY_BASELINE_CLAIM.value:
        result = ClaimGateResult.LEGACY_ONLY
        reason_codes.append("LEGACY_EVIDENCE_MAY_ONLY_SUPPORT_LEGACY_BASELINE")
    if result == ClaimGateResult.ALLOW and any(
        record["origin"] == EvidenceOrigin.SYNTHETIC.value or record["synthetic_or_real"] == "SYNTHETIC"
        for record in resolved_artifacts
    ):
        result = ClaimGateResult.ALLOW_WITH_CAVEAT
        reason_codes.append("SYNTHETIC_EVIDENCE_ENGINEERING_SCOPE_ONLY")

    allowed_wording = [claim["statement"]] if result in {
        ClaimGateResult.ALLOW, ClaimGateResult.ALLOW_WITH_CAVEAT,
        ClaimGateResult.LEGACY_ONLY,
    } else []
    forbidden_wording = [] if result == ClaimGateResult.ALLOW else [
        "Do not present this claim outside the gate-approved scope",
    ]
    required_actions = {
        ClaimGateResult.BLOCK: ["Supply valid ref+digest evidence and narrow the claim scope"],
        ClaimGateResult.NEEDS_RERUN: ["Run and record an approved CURRENT_V2 real execution"],
        ClaimGateResult.NEEDS_RECOMPUTATION: ["Recompute the metric from a complete digest-verified population"],
        ClaimGateResult.NEEDS_EXTERNAL_CONFIRMATION: ["Attach a local digest-verified authoritative upstream snapshot"],
    }.get(result, [])
    value = {
        "schema_version": SCHEMA_VERSIONS["claim_gate_report"],
        "claim_gate_report_id": "pending", "claim": claim_link(claim),
        "gate_result": result.value, "reason_codes": sorted(set(reason_codes)),
        "blocking_refs": sorted(blocking_refs, key=lambda item: (item["ref"], item["digest"])),
        "required_actions": required_actions, "allowed_wording": allowed_wording,
        "forbidden_wording": forbidden_wording,
        "allowed_report_sections": list(claim["requested_report_sections"]) if result != ClaimGateResult.BLOCK else [],
        "ppt_usage": list(claim["requested_ppt_usage"]) if result in {ClaimGateResult.ALLOW, ClaimGateResult.ALLOW_WITH_CAVEAT} else [],
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "registry_version": REGISTRY_VERSION,
    }
    report = identify(value)
    validate_document_or_raise(report)
    return report
