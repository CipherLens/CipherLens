"""CipherLens evaluation evidence and report-claim foundation."""

from evaluation_evidence.canonical import canonical_bytes, document_digest, identify
from evaluation_evidence.model import (
    ClaimGateResult,
    ClaimTaxonomy,
    EvidenceOrigin,
    FindingStatus,
    InventoryState,
    LegacyReusePolicy,
    RecomputeStatus,
    ValidationMaturity,
)
from evaluation_evidence.registry import INITIAL_METRIC_REGISTRY, validate_document, validate_document_or_raise

__all__ = [
    "ClaimGateResult", "ClaimTaxonomy", "EvidenceOrigin", "FindingStatus",
    "INITIAL_METRIC_REGISTRY", "InventoryState", "LegacyReusePolicy",
    "RecomputeStatus", "ValidationMaturity", "canonical_bytes", "document_digest",
    "identify", "validate_document", "validate_document_or_raise",
]
