"""Construction of the provenance-only Evaluation Evidence Ledger."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from evaluation_evidence.canonical import identify
from evaluation_evidence.model import REGISTRY_VERSION, SCHEMA_VERSIONS
from evaluation_evidence.registry import validate_document_or_raise


def build_evidence_ledger(
    *, git_revision: str, artifact_records: Iterable[Mapping[str, Any]] = (),
    test_run_records: Iterable[Mapping[str, Any]] = (),
    experiment_units: Iterable[Mapping[str, Any]] = (),
    metric_records: Iterable[Mapping[str, Any]] = (),
    finding_records: Iterable[Mapping[str, str]] = (),
    claim_records: Iterable[Mapping[str, Any]] = (),
    producer_id: str = "evaluation-evidence-ledger", producer_version: str = "0.1",
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSIONS["ledger"], "ledger_id": "pending",
        "producer": {"producer_id": producer_id, "producer_version": producer_version},
        "git_revision": git_revision, "registry_version": REGISTRY_VERSION,
        "artifact_records": [dict(item) for item in artifact_records],
        "test_run_records": [dict(item) for item in test_run_records],
        "experiment_units": [dict(item) for item in experiment_units],
        "metric_records": [dict(item) for item in metric_records],
        "finding_records": [dict(item) for item in finding_records],
        "claim_records": [dict(item) for item in claim_records],
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result
