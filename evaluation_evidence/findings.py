"""Security Finding Ledger construction and deterministic status gates."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any, Callable, Iterable, Mapping

from evaluation_evidence.canonical import canonical_json_bytes, identify
from evaluation_evidence.lineage import validate_link
from evaluation_evidence.model import EvidenceOrigin, FindingStatus, REGISTRY_VERSION, SCHEMA_VERSIONS
from evaluation_evidence.registry import validate_document_or_raise, validate_finding_record_or_raise


class FindingGateError(ValueError):
    pass


def _finding_id(value: Mapping[str, Any]) -> str:
    body = deepcopy(dict(value))
    body.pop("finding_id", None)
    return "finding:" + hashlib.sha256(canonical_json_bytes(body)).hexdigest()


def build_finding(
    *, finding_status: FindingStatus | str, target_scope: Mapping[str, str],
    affected_component: str, family: str, contract: Mapping[str, str] | None = None,
    candidate_binding: Mapping[str, str] | None = None,
    execution_verdict: Mapping[str, str] | None = None,
    violation_package: Mapping[str, str] | None = None,
    reproduction_refs: Iterable[Mapping[str, str]] = (),
    impact_refs: Iterable[Mapping[str, str]] = (), upstream_refs: Iterable[Mapping[str, str]] = (),
    fix_refs: Iterable[Mapping[str, str]] = (), advisory_refs: Iterable[Mapping[str, str]] = (),
    origin: EvidenceOrigin | str, public_disclosure_state: str,
    allowed_claim_boundary: str,
) -> dict[str, Any]:
    value = {
        "finding_id": "pending",
        "finding_status": finding_status.value if isinstance(finding_status, FindingStatus) else finding_status,
        "target_scope": dict(target_scope), "affected_component": affected_component, "family": family,
        "contract": dict(contract) if contract is not None else None,
        "candidate_binding": dict(candidate_binding) if candidate_binding is not None else None,
        "execution_verdict": dict(execution_verdict) if execution_verdict is not None else None,
        "violation_package": dict(violation_package) if violation_package is not None else None,
        "reproduction_refs": [dict(item) for item in reproduction_refs],
        "impact_refs": [dict(item) for item in impact_refs],
        "upstream_refs": [dict(item) for item in upstream_refs],
        "fix_refs": [dict(item) for item in fix_refs],
        "advisory_refs": [dict(item) for item in advisory_refs],
        "origin": origin.value if isinstance(origin, EvidenceOrigin) else origin,
        "public_disclosure_state": public_disclosure_state,
        "allowed_claim_boundary": allowed_claim_boundary,
    }
    value["finding_id"] = _finding_id(value)
    return value


def finding_link(finding: Mapping[str, Any]) -> dict[str, str]:
    validate_finding_record_or_raise(finding)
    return {
        "ref": f"security-finding:{finding['finding_id']}",
        "digest": hashlib.sha256(canonical_json_bytes(finding)).hexdigest(),
    }


def _artifact_index(records: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], Mapping[str, Any]]:
    return {
        (str(record.get("artifact_ref")), str(record.get("artifact_digest"))): record
        for record in records if record.get("artifact_digest") is not None
    }


def _require_links(
    links: Iterable[Mapping[str, str]], artifact_records: Iterable[Mapping[str, Any]],
    resolver: Callable[[str, str], bool], *, artifact_types: set[str] | None = None,
    origin: str | None = None, real: bool | None = None,
) -> list[Mapping[str, Any]]:
    index = _artifact_index(artifact_records)
    matched: list[Mapping[str, Any]] = []
    for link in links:
        if validate_link(link) or not resolver(str(link["ref"]), str(link["digest"])):
            raise FindingGateError("finding evidence ref is missing or digest-invalid")
        record = index.get((str(link["ref"]), str(link["digest"])))
        if record is None:
            raise FindingGateError("finding evidence lacks an ArtifactRecord")
        if artifact_types is not None and record.get("artifact_type") not in artifact_types:
            raise FindingGateError("finding evidence has the wrong artifact type")
        if origin is not None and record.get("origin") != origin:
            raise FindingGateError("finding evidence has the wrong origin")
        if real is not None and (record.get("synthetic_or_real") == "REAL") is not real:
            raise FindingGateError("finding evidence has the wrong synthetic/real scope")
        matched.append(record)
    return matched


def validate_finding_status(
    finding: Mapping[str, Any], *, artifact_records: Iterable[Mapping[str, Any]],
    resolver: Callable[[str, str], bool],
    document_resolver: Callable[[str, str], Mapping[str, Any] | None] | None = None,
) -> None:
    status = FindingStatus(finding["finding_status"])
    all_links: list[Mapping[str, str]] = []
    for key in ("contract", "candidate_binding", "execution_verdict", "violation_package"):
        if finding.get(key) is not None:
            all_links.append(finding[key])
    for key in ("reproduction_refs", "impact_refs", "upstream_refs", "fix_refs", "advisory_refs"):
        all_links.extend(finding.get(key, []))
    _require_links(all_links, artifact_records, resolver)
    if status in {FindingStatus.NOT_A_FINDING, FindingStatus.HYPOTHESIS, FindingStatus.HARDENING_ONLY, FindingStatus.SAFE_NEGATIVE}:
        return
    if status == FindingStatus.REPRODUCED_RELATION_BEHAVIOR and not finding["reproduction_refs"]:
        raise FindingGateError("reproduced relation behavior requires reproduction evidence")
    if status == FindingStatus.V2_VIOLATED_WITNESS:
        if finding.get("execution_verdict") is None or finding.get("violation_package") is None:
            raise FindingGateError("V2_VIOLATED_WITNESS requires Verdict and ViolationPackage")
        _require_links(
            [finding["execution_verdict"], finding["violation_package"]], artifact_records, resolver,
            artifact_types={"execution_verdict", "violation_package"},
            origin=EvidenceOrigin.CURRENT_V2.value, real=True,
        )
        if document_resolver is None:
            raise FindingGateError("canonical Verdict documents are required for V2 violation gate")
        verdict = document_resolver(finding["execution_verdict"]["ref"], finding["execution_verdict"]["digest"])
        package = document_resolver(finding["violation_package"]["ref"], finding["violation_package"]["digest"])
        from execution_model.registry import validate_artifact
        if verdict and validate_artifact(verdict):
            raise FindingGateError("execution Verdict fails its frozen schema")
        if package and validate_artifact(package):
            raise FindingGateError("ViolationPackage fails its frozen schema")
        if not verdict or verdict.get("schema_version") != "cipherlens.execution_verdict.v0.1" or verdict.get("verdict") != "VIOLATED":
            raise FindingGateError("finding does not reference a canonical VIOLATED Verdict")
        if not package or package.get("schema_version") != "cipherlens.violation_evidence_package.v0.1":
            raise FindingGateError("finding does not reference a canonical ViolationPackage")
    if status == FindingStatus.IMPACT_ANALYZED:
        if not finding["impact_refs"]:
            raise FindingGateError("IMPACT_ANALYZED requires independent impact evidence")
        _require_links(finding["impact_refs"], artifact_records, resolver, artifact_types={"impact_evidence"})
    if status == FindingStatus.REPORTED_UPSTREAM:
        _require_links(finding["upstream_refs"], artifact_records, resolver, artifact_types={"upstream_submission"})
        if not finding["upstream_refs"]:
            raise FindingGateError("REPORTED_UPSTREAM requires submission evidence")
    if status == FindingStatus.UPSTREAM_ACKNOWLEDGED:
        if not finding["upstream_refs"]:
            raise FindingGateError("UPSTREAM_ACKNOWLEDGED requires external response evidence")
        _require_links(
            finding["upstream_refs"], artifact_records, resolver,
            artifact_types={"upstream_response"}, origin=EvidenceOrigin.EXTERNAL_UPSTREAM.value,
        )
    if status == FindingStatus.FIX_CONFIRMED:
        types = {record["artifact_type"] for record in _require_links(finding["fix_refs"], artifact_records, resolver)}
        if not {"upstream_fix_revision", "regression_test_run"}.issubset(types):
            raise FindingGateError("FIX_CONFIRMED requires fix revision and regression evidence")
    if status == FindingStatus.CVE_OR_ADVISORY_CONFIRMED:
        if not finding["advisory_refs"]:
            raise FindingGateError("CVE/advisory status requires authoritative advisory evidence")
        _require_links(
            finding["advisory_refs"], artifact_records, resolver,
            artifact_types={"authoritative_advisory"}, origin=EvidenceOrigin.EXTERNAL_UPSTREAM.value,
        )


def build_security_finding_ledger(
    *, findings: Iterable[Mapping[str, Any]], git_revision: str,
    artifact_records: Iterable[Mapping[str, Any]], resolver: Callable[[str, str], bool],
    document_resolver: Callable[[str, str], Mapping[str, Any] | None] | None = None,
    producer_id: str = "security-finding-ledger", producer_version: str = "0.1",
) -> dict[str, Any]:
    records = [deepcopy(dict(item)) for item in findings]
    artifacts = list(artifact_records)
    for finding in records:
        if finding.get("finding_id") != _finding_id(finding):
            raise FindingGateError("finding identity mismatch")
        validate_finding_status(
            finding, artifact_records=artifacts, resolver=resolver,
            document_resolver=document_resolver,
        )
    value = {
        "schema_version": SCHEMA_VERSIONS["finding_ledger"], "ledger_id": "pending",
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "git_revision": git_revision, "registry_version": REGISTRY_VERSION, "findings": records,
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result
