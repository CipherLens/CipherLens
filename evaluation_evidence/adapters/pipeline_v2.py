"""Adapter from frozen pipeline-v2 ref/digest artifacts into observations."""

from __future__ import annotations

from typing import Any, Callable

from evaluation_evidence.inventory import build_artifact_record
from evaluation_evidence.model import EvidenceOrigin, InventoryState, ValidationMaturity


def observe_pipeline_artifact(
    *, artifact_ref: str, artifact_digest: str, artifact_type: str,
    artifact_schema_version: str, git_revision: str,
    resolver: Callable[[str, str], bool], synthetic: bool,
) -> dict[str, Any]:
    if not resolver(artifact_ref, artifact_digest):
        raise ValueError("pipeline artifact ref/digest is not resolvable")
    maturity = [ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED]
    return build_artifact_record(
        artifact_ref=artifact_ref, artifact_digest=artifact_digest,
        artifact_type=artifact_type, artifact_schema_version=artifact_schema_version,
        media_type="application/json", producer_id="pipeline-v2-adapter", producer_version="0.1",
        git_revision=git_revision, origin=EvidenceOrigin.CURRENT_V2,
        inventory_state=InventoryState.VERIFIED_PRESENT, validation_maturity=maturity,
        execution_scope="pipeline-v2", synthetic_or_real="SYNTHETIC" if synthetic else "REAL",
        public_disclosure_state="LOCAL_ONLY", source_location="pipeline_v2/content-addressed-store",
    )
