"""Offline external/upstream snapshot adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evaluation_evidence.inventory import build_artifact_record, observe_repository_file
from evaluation_evidence.model import EvidenceOrigin, ExternalEvidenceRecord, InventoryState


def import_external_snapshot(
    repo_root: str | Path, *, url: str, snapshot_location: str | None,
    publisher_identity: str, evidence_type: str, authority_classification: str,
    git_revision: str, retrieved_at_telemetry: str | None = None,
) -> ExternalEvidenceRecord:
    notes = (
        f"URL={url}", f"publisher={publisher_identity}",
        f"authority={authority_classification}",
        "External status is not inferred from URL text",
    )
    if snapshot_location is None:
        record = build_artifact_record(
            artifact_ref=f"external-reference:{url}", artifact_digest=None,
            artifact_type=evidence_type, artifact_schema_version="external-evidence.v0.1",
            media_type="application/octet-stream", producer_id="external-evidence-adapter",
            producer_version="0.1", git_revision=git_revision,
            origin=EvidenceOrigin.EXTERNAL_UPSTREAM,
            inventory_state=InventoryState.PRESENT_UNVERIFIED, validation_maturity=(),
            execution_scope="external-reference-only", synthetic_or_real="REAL",
            public_disclosure_state="PUBLIC", source_location="external/reference-only",
            notes=notes,
        )
    else:
        record = observe_repository_file(
            repo_root, snapshot_location, artifact_type=evidence_type, git_revision=git_revision,
            origin=EvidenceOrigin.EXTERNAL_UPSTREAM, producer_id="external-evidence-adapter",
            artifact_schema_version="external-evidence.v0.1", execution_scope="offline-snapshot",
            synthetic_or_real="REAL", public_disclosure_state="PUBLIC",
        )
        record = dict(record)
        record["notes"] = sorted(set(record["notes"] + list(notes)))
        from evaluation_evidence.canonical import identify
        from evaluation_evidence.registry import validate_document_or_raise
        record = identify(record)
        validate_document_or_raise(record)
    return ExternalEvidenceRecord(
        url=url, publisher_identity=publisher_identity, evidence_type=evidence_type,
        authority_classification=authority_classification, record=record,
        telemetry={"retrieved_at": retrieved_at_telemetry} if retrieved_at_telemetry else {},
    )
