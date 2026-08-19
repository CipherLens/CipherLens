"""Evidence status rules: provenance, not retrieval confidence, is authority."""

from __future__ import annotations

from enum import Enum
from typing import Mapping


class EvidenceStatus(str, Enum):
    VERIFIED = "VERIFIED"
    CANDIDATE = "CANDIDATE"
    REJECTED = "REJECTED"


def verify_evidence_record(record: Mapping[str, object]) -> EvidenceStatus:
    """Classify evidence without allowing cards or RAG scores to self-verify."""
    evidence_type = str(record.get("evidence_type", ""))
    lifecycle = str(record.get("lifecycle", "")).lower()
    runtime = str(record.get("runtime_status", "")).lower()
    if evidence_type in {"API_CARD", "RAG_RESULT", "LEGACY_SCORE"}:
        return EvidenceStatus.CANDIDATE
    if lifecycle in {"draft", "partial", "blocked", "needs_review"} or runtime == "blocked":
        return EvidenceStatus.CANDIDATE
    if evidence_type in {"SOURCE_SNIPPET", "HEADER_SIGNATURE"}:
        required = ("symbol", "file_ref", "file_digest", "snippet_digest")
        if all(record.get(key) for key in required):
            return EvidenceStatus.VERIFIED
    return EvidenceStatus.CANDIDATE
