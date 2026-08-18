"""Closed internal vocabulary for Contract-guided Matcher v0.1."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import Enum
import hashlib
import json
from typing import Any, Mapping, Sequence


MATCHER_VERSION = "v0.1"
MATCHER_TRACE_SCHEMA_VERSION = "cipherlens.matcher_trace.v0.1"
RECALL_QUERY_SCHEMA_VERSION = "cipherlens.recall_query.v0.1"


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def semantic_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class MatcherStage(str, Enum):
    RECALLED = "RECALLED"
    ASSEMBLED = "ASSEMBLED"
    PROPOSAL_UNAVAILABLE = "PROPOSAL_UNAVAILABLE"
    PROPOSED = "PROPOSED"
    RESOLVED = "RESOLVED"
    INELIGIBLE = "INELIGIBLE"
    INDETERMINATE = "INDETERMINATE"
    ELIGIBLE = "ELIGIBLE"
    OBSERVABILITY_BLOCKED = "OBSERVABILITY_BLOCKED"
    RANKING_READY = "RANKING_READY"
    BINDING_REJECTED = "BINDING_REJECTED"
    MATCHED = "MATCHED"


class MatcherRunOutcome(str, Enum):
    MATCH_FOUND = "MATCH_FOUND"
    NO_ELIGIBLE_CANDIDATE = "NO_ELIGIBLE_CANDIDATE"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    PROVIDER_BLOCKED = "PROVIDER_BLOCKED"
    CANDIDATES_EXHAUSTED = "CANDIDATES_EXHAUSTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    INPUT_INVALID = "INPUT_INVALID"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ObservabilityStatus(str, Enum):
    RESOLVABLE = "RESOLVABLE"
    UNRESOLVABLE = "UNRESOLVABLE"
    INCOMPLETE = "INCOMPLETE"


class VerifierType(str, Enum):
    SYMBOL_EXISTENCE = "SYMBOL_EXISTENCE"
    SIGNATURE_TYPE = "SIGNATURE_TYPE"
    PARAMETER_ROLE = "PARAMETER_ROLE"
    OWNERSHIP_LIFETIME = "OWNERSHIP_LIFETIME"
    DOCUMENTED_CONTRACT = "DOCUMENTED_CONTRACT"
    SOURCE_CONFIRMATION = "SOURCE_CONFIRMATION"
    HEADER_CONFIRMATION = "HEADER_CONFIRMATION"
    OBSERVABLE_CHANNEL_CHECK = "OBSERVABLE_CHANNEL_CHECK"
    STATE_CONTINUITY_CHECK = "STATE_CONTINUITY_CHECK"


class EvidenceClass(str, Enum):
    SOURCE = "SOURCE"
    HEADER = "HEADER"
    OFFICIAL_DOCUMENT = "OFFICIAL_DOCUMENT"
    STATIC_INSPECTION = "STATIC_INSPECTION"
    TEST_ARTIFACT = "TEST_ARTIFACT"
    FIXTURE = "FIXTURE"
    RAG_HIT = "RAG_HIT"
    API_CARD = "API_CARD"
    RECIPE_HINT = "RECIPE_HINT"
    LEGACY_HINT = "LEGACY_HINT"
    FEEDBACK_HINT = "FEEDBACK_HINT"


TRUSTED_EVIDENCE_CLASSES = frozenset(
    {
        EvidenceClass.SOURCE,
        EvidenceClass.HEADER,
        EvidenceClass.OFFICIAL_DOCUMENT,
        EvidenceClass.STATIC_INSPECTION,
        EvidenceClass.TEST_ARTIFACT,
        EvidenceClass.FIXTURE,
    }
)


@dataclass(frozen=True)
class TargetScope:
    library: str
    version: str
    surface_ref: str

    def __post_init__(self) -> None:
        if not self.library or self.library != self.library.lower():
            raise ValueError("target scope library must be non-empty lowercase")
        if not self.version or not self.surface_ref:
            raise ValueError("target scope version and surface_ref are required")

    def to_dict(self) -> dict[str, str]:
        return {
            "library": self.library,
            "version": self.version,
            "surface_ref": self.surface_ref,
        }


@dataclass(frozen=True)
class MatcherBudgets:
    max_recall_candidates: int = 32
    max_proposals_per_candidate: int = 2
    max_evidence_rounds: int = 2
    max_binding_attempts: int = 16

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_recall_candidates": self.max_recall_candidates,
            "max_proposals_per_candidate": self.max_proposals_per_candidate,
            "max_evidence_rounds": self.max_evidence_rounds,
            "max_binding_attempts": self.max_binding_attempts,
        }


def _identity_composition(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove evidence/operational helpers from candidate semantic identity."""

    ignored = {
        "_binding_mappings",
        "retrieval_metadata",
        "ranking_metadata",
        "evidence_metadata",
        "telemetry",
    }
    return {
        str(key): deepcopy(child)
        for key, child in value.items()
        if str(key) not in ignored and not str(key).startswith("_")
    }


def expected_candidate_id(
    target_scope: TargetScope,
    subject_refs: Sequence[str],
    symbol_refs: Sequence[str],
    surface_composition: Mapping[str, Any],
) -> str:
    semantic = {
        "library": target_scope.library,
        "version": target_scope.version,
        "surface_ref": target_scope.surface_ref,
        "subject_refs": sorted(dict.fromkeys(subject_refs)),
        "symbol_refs": sorted(dict.fromkeys(symbol_refs)),
        "surface_composition": _identity_composition(surface_composition),
    }
    return "matcher-candidate:" + semantic_digest(semantic)


@dataclass(frozen=True)
class RetrievalRecord:
    retrieval_id: str
    backend: str
    query_ref: str
    entity_ref: str
    entity_kind: str
    evidence_refs: tuple[str, ...]
    rank: int
    score: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "retrieval_id": self.retrieval_id,
            "backend": self.backend,
            "query_ref": self.query_ref,
            "entity_ref": self.entity_ref,
            "entity_kind": self.entity_kind,
            "evidence_refs": list(self.evidence_refs),
            "rank": self.rank,
            "score": self.score,
            "metadata": deepcopy(dict(self.metadata)),
        }


@dataclass(frozen=True)
class AssemblyRecord:
    assembly_id: str
    seed_refs: tuple[str, ...]
    relation_reasons: tuple[str, ...]
    candidate_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "assembly_id": self.assembly_id,
            "seed_refs": list(self.seed_refs),
            "relation_reasons": list(self.relation_reasons),
            "candidate_ref": self.candidate_ref,
        }


@dataclass(frozen=True)
class MatcherCandidate:
    candidate_id: str
    target_scope: TargetScope
    subject_refs: tuple[str, ...]
    symbol_refs: tuple[str, ...]
    surface_composition: Mapping[str, Any]
    surface_relations: tuple[Mapping[str, Any], ...] = ()
    evidence_refs: tuple[str, ...] = ()
    retrieval_records: tuple[RetrievalRecord, ...] = ()
    proposal_refs: tuple[str, ...] = ()
    profile_refs: tuple[str, ...] = ()
    eligibility_refs: tuple[str, ...] = ()
    observability_records: tuple[str, ...] = ()
    ranking_record_ref: str | None = None
    binding_attempt_refs: tuple[str, ...] = ()
    stage_status: MatcherStage = MatcherStage.ASSEMBLED
    rejection_reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        expected = expected_candidate_id(
            self.target_scope,
            self.subject_refs,
            self.symbol_refs,
            self.surface_composition,
        )
        if self.candidate_id != expected:
            raise ValueError("candidate_id does not match semantic surface")
        if len(set(self.subject_refs)) != len(self.subject_refs):
            raise ValueError("duplicate subject_refs")
        if len(set(self.symbol_refs)) != len(self.symbol_refs):
            raise ValueError("duplicate symbol_refs")

    @classmethod
    def create(
        cls,
        *,
        target_scope: TargetScope,
        subject_refs: Sequence[str],
        symbol_refs: Sequence[str],
        surface_composition: Mapping[str, Any],
        surface_relations: Sequence[Mapping[str, Any]] = (),
        evidence_refs: Sequence[str] = (),
        retrieval_records: Sequence[RetrievalRecord] = (),
    ) -> "MatcherCandidate":
        subjects = tuple(sorted(dict.fromkeys(subject_refs)))
        symbols = tuple(sorted(dict.fromkeys(symbol_refs)))
        composition = deepcopy(dict(surface_composition))
        return cls(
            candidate_id=expected_candidate_id(
                target_scope, subjects, symbols, composition
            ),
            target_scope=target_scope,
            subject_refs=subjects,
            symbol_refs=symbols,
            surface_composition=composition,
            surface_relations=tuple(
                sorted(
                    (deepcopy(dict(item)) for item in surface_relations),
                    key=lambda item: canonical_json_bytes(item),
                )
            ),
            evidence_refs=tuple(sorted(dict.fromkeys(evidence_refs))),
            retrieval_records=tuple(retrieval_records),
        )

    def evolve(self, **changes: Any) -> "MatcherCandidate":
        return replace(self, **changes)

    def semantic_summary(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "target_scope": self.target_scope.to_dict(),
            "subject_refs": list(self.subject_refs),
            "symbol_refs": list(self.symbol_refs),
            "surface_composition": _identity_composition(self.surface_composition),
            "surface_relations": [deepcopy(dict(x)) for x in self.surface_relations],
        }


@dataclass(frozen=True)
class FactResolutionRecord:
    record_id: str
    candidate_ref: str
    proposal_ref: str
    claim_ref: str
    requested_fact_type: str
    target_subject_ref: str
    verifier_type: VerifierType
    verifier_version: str
    input_evidence_refs: tuple[str, ...]
    input_evidence_digests: tuple[str, ...]
    assertion: str
    resulting_epistemic_status: str
    resulting_fact_ref: str | None
    reason_code: str
    missing_requirements: tuple[str, ...] = ()
    fact: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "candidate_ref": self.candidate_ref,
            "proposal_ref": self.proposal_ref,
            "claim_ref": self.claim_ref,
            "requested_fact_type": self.requested_fact_type,
            "target_subject_ref": self.target_subject_ref,
            "verifier_type": self.verifier_type.value,
            "verifier_version": self.verifier_version,
            "input_evidence_refs": list(self.input_evidence_refs),
            "input_evidence_digests": list(self.input_evidence_digests),
            "assertion": self.assertion,
            "resulting_epistemic_status": self.resulting_epistemic_status,
            "resulting_fact_ref": self.resulting_fact_ref,
            "reason_code": self.reason_code,
            "missing_requirements": list(self.missing_requirements),
        }


@dataclass(frozen=True)
class ObservabilityRecord:
    record_id: str
    candidate_ref: str
    proposal_ref: str
    profile_ref: str
    eligibility_ref: str
    status: ObservabilityStatus
    observable_assignments: tuple[Mapping[str, Any], ...]
    verified_fact_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "candidate_ref": self.candidate_ref,
            "proposal_ref": self.proposal_ref,
            "profile_ref": self.profile_ref,
            "eligibility_ref": self.eligibility_ref,
            "status": self.status.value,
            "observable_assignments": [deepcopy(dict(x)) for x in self.observable_assignments],
            "verified_fact_refs": list(self.verified_fact_refs),
            "evidence_refs": list(self.evidence_refs),
            "missing_requirements": list(self.missing_requirements),
            "reason_codes": list(self.reason_codes),
        }


@dataclass(frozen=True)
class RankingRecord:
    ranking_id: str
    candidate_ref: str
    proposal_ref: str
    feature_vector: tuple[int, ...]
    feature_breakdown: Mapping[str, int]
    position: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "ranking_id": self.ranking_id,
            "candidate_ref": self.candidate_ref,
            "proposal_ref": self.proposal_ref,
            "feature_vector": list(self.feature_vector),
            "feature_breakdown": dict(self.feature_breakdown),
            "position": self.position,
        }


@dataclass(frozen=True)
class MatcherTelemetry:
    timestamps: Mapping[str, str] = field(default_factory=dict)
    latency_ms: Mapping[str, float] = field(default_factory=dict)
    token_usage: Mapping[str, int] = field(default_factory=dict)
    billing: Mapping[str, Any] = field(default_factory=dict)
    host: str | None = None
    process_id: int | None = None
