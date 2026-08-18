"""Matcher-facing knowledge abstraction and deterministic fixture backend."""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from matcher.model import EvidenceClass, TargetScope
from matcher.query import RecallQuery


@dataclass(frozen=True)
class EvidenceItem:
    evidence_ref: str
    source_type: EvidenceClass
    target_scope: TargetScope
    subject_refs: tuple[str, ...]
    symbol_refs: tuple[str, ...]
    artifact_ref: str
    artifact_digest: str
    initial_epistemic_status: str
    fact_payloads: tuple[Mapping[str, Any], ...] = ()
    retrieval_provenance: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def profile_kind(self) -> str:
        return {
            EvidenceClass.SOURCE: "source",
            EvidenceClass.HEADER: "source",
            EvidenceClass.OFFICIAL_DOCUMENT: "official_doc",
            EvidenceClass.STATIC_INSPECTION: "test",
            EvidenceClass.TEST_ARTIFACT: "test",
            EvidenceClass.FIXTURE: "test_fixture",
            EvidenceClass.RAG_HIT: "rag",
            EvidenceClass.API_CARD: "api_card",
            EvidenceClass.RECIPE_HINT: "adapter_recipe",
            EvidenceClass.LEGACY_HINT: "rag",
            EvidenceClass.FEEDBACK_HINT: "rag",
        }[self.source_type]

    def to_profile_evidence(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_ref,
            "kind": self.profile_kind(),
            "path": self.artifact_ref,
            "sha256": self.artifact_digest,
        }


@dataclass(frozen=True)
class KnowledgeSeed:
    entity_ref: str
    entity_kind: str
    target_scope: TargetScope
    subject_refs: tuple[str, ...]
    symbol_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    related_refs: tuple[str, ...] = ()
    surface_composition: Mapping[str, Any] = field(default_factory=dict)
    surface_relations: tuple[Mapping[str, Any], ...] = ()
    score: float | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


class TargetKnowledgeBase(ABC):
    """Stable interface; vector retrieval is only one possible implementation."""

    backend_name = "abstract"

    @abstractmethod
    def search(
        self, query: RecallQuery, target_scope: TargetScope, limit: int
    ) -> Sequence[KnowledgeSeed]:
        raise NotImplementedError

    @abstractmethod
    def get_evidence(self, evidence_ref: str) -> EvidenceItem | None:
        raise NotImplementedError

    @abstractmethod
    def get_symbol(self, symbol_ref: str) -> Mapping[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def get_subject(self, subject_ref: str) -> Mapping[str, Any] | None:
        raise NotImplementedError

    @abstractmethod
    def related_surfaces(self, entity_ref: str) -> Sequence[KnowledgeSeed]:
        raise NotImplementedError

    @abstractmethod
    def find_evidence(
        self,
        *,
        target_scope: TargetScope,
        subject_ref: str | None = None,
        symbol_ref: str | None = None,
        source_types: Sequence[EvidenceClass] = (),
    ) -> Sequence[EvidenceItem]:
        raise NotImplementedError


class SyntheticKnowledgeBackend(TargetKnowledgeBase):
    """In-memory, deterministic, no-network backend for default tests."""

    backend_name = "synthetic"

    def __init__(
        self,
        *,
        seeds: Sequence[KnowledgeSeed] = (),
        evidence: Sequence[EvidenceItem] = (),
        subjects: Mapping[str, Mapping[str, Any]] | None = None,
        symbols: Mapping[str, Mapping[str, Any]] | None = None,
        related: Mapping[str, Sequence[KnowledgeSeed]] | None = None,
    ) -> None:
        self._seeds = tuple(sorted(seeds, key=lambda item: item.entity_ref))
        self._evidence = {item.evidence_ref: item for item in evidence}
        self._subjects = {
            key: deepcopy(dict(value)) for key, value in (subjects or {}).items()
        }
        self._symbols = {
            key: deepcopy(dict(value)) for key, value in (symbols or {}).items()
        }
        self._related = {
            key: tuple(sorted(value, key=lambda item: item.entity_ref))
            for key, value in (related or {}).items()
        }
        self.search_count = 0
        self.network_call_count = 0

    def search(
        self, query: RecallQuery, target_scope: TargetScope, limit: int
    ) -> Sequence[KnowledgeSeed]:
        del query
        self.search_count += 1
        matches = [
            item
            for item in self._seeds
            if item.target_scope.library == target_scope.library
            and item.target_scope.version == target_scope.version
            and item.target_scope.surface_ref == target_scope.surface_ref
        ]
        return tuple(matches[:limit])

    def get_evidence(self, evidence_ref: str) -> EvidenceItem | None:
        return self._evidence.get(evidence_ref)

    def get_symbol(self, symbol_ref: str) -> Mapping[str, Any] | None:
        value = self._symbols.get(symbol_ref)
        return deepcopy(value) if value is not None else None

    def get_subject(self, subject_ref: str) -> Mapping[str, Any] | None:
        value = self._subjects.get(subject_ref)
        return deepcopy(value) if value is not None else None

    def related_surfaces(self, entity_ref: str) -> Sequence[KnowledgeSeed]:
        return self._related.get(entity_ref, ())

    def find_evidence(
        self,
        *,
        target_scope: TargetScope,
        subject_ref: str | None = None,
        symbol_ref: str | None = None,
        source_types: Sequence[EvidenceClass] = (),
    ) -> Sequence[EvidenceItem]:
        allowed = set(source_types)
        result = []
        for item in self._evidence.values():
            if item.target_scope != target_scope:
                continue
            if subject_ref is not None and subject_ref not in item.subject_refs:
                continue
            if symbol_ref is not None and symbol_ref not in item.symbol_refs:
                continue
            if allowed and item.source_type not in allowed:
                continue
            result.append(item)
        return tuple(sorted(result, key=lambda item: item.evidence_ref))


def artifact_exists_and_matches(item: EvidenceItem, repo_root: str | Path) -> bool:
    import hashlib

    path = Path(repo_root) / item.artifact_ref
    if not path.is_file():
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == item.artifact_digest
