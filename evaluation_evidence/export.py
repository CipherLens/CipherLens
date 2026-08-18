"""Machine-readable report/PPT evidence views; no presentation rendering."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from evaluation_evidence.model import ClaimGateResult, SCHEMA_VERSIONS
from evaluation_evidence.canonical import document_digest
from evaluation_evidence.registry import validate_document_or_raise


def structured_evidence_export(
    ledger: Mapping[str, Any], gate_reports: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    validate_document_or_raise(ledger)
    if ledger["schema_version"] != SCHEMA_VERSIONS["ledger"]:
        raise ValueError("expected Evaluation Evidence Ledger")
    reports = [dict(item) for item in gate_reports]
    for report in reports:
        validate_document_or_raise(report)
    permitted = {
        ClaimGateResult.ALLOW.value, ClaimGateResult.ALLOW_WITH_CAVEAT.value,
        ClaimGateResult.LEGACY_ONLY.value,
    }
    return {
        "schema_version": "cipherlens.structured_evidence_export.v0.1",
        "ledger": {"ref": f"evaluation-ledger:{ledger['ledger_id']}", "digest": document_digest(ledger)},
        "report_evidence_view": [report for report in reports if report["gate_result"] in permitted],
        "blocked_claim_view": [report for report in reports if report["gate_result"] not in permitted],
        "ppt_evidence_view": [report for report in reports if report["ppt_usage"]],
    }
