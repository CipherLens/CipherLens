"""Read-only legacy artifact importer; semantic labels are never upgraded."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evaluation_evidence.inventory import observe_repository_file
from evaluation_evidence.model import EvidenceOrigin


FORBIDDEN_LEGACY_UPGRADES = frozenset({"SATISFIED", "VIOLATED", "UNKNOWN"})


def import_legacy_artifact(
    repo_root: str | Path, relative_location: str, *, artifact_type: str,
    legacy_semantic_label: str, git_revision: str,
    origin: EvidenceOrigin = EvidenceOrigin.LEGACY,
    producer_id: str = "legacy-artifact-importer",
) -> dict[str, Any]:
    if origin not in {EvidenceOrigin.LEGACY, EvidenceOrigin.CURRENT_NON_V2}:
        raise ValueError("legacy importer only accepts LEGACY or CURRENT_NON_V2 origin")
    if legacy_semantic_label in FORBIDDEN_LEGACY_UPGRADES:
        raise ValueError("legacy labels cannot be rewritten as canonical ExecutionVerdict")
    record = observe_repository_file(
        repo_root, relative_location, artifact_type=artifact_type, git_revision=git_revision,
        origin=origin, producer_id=producer_id, artifact_schema_version="legacy-unmodified",
        execution_scope="legacy-read-only-import", synthetic_or_real="REAL",
        public_disclosure_state="UNKNOWN",
    )
    record = dict(record)
    record["notes"] = sorted(set(record["notes"] + [f"legacy_semantic_label={legacy_semantic_label}", "No legacy verdict conversion was performed"]))
    from evaluation_evidence.canonical import identify
    from evaluation_evidence.registry import validate_document_or_raise
    record = identify(record)
    validate_document_or_raise(record)
    return record
