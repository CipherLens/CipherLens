"""Offline production adapters for Matcher knowledge and deterministic re-entry."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

from matcher.knowledge import EvidenceItem, KnowledgeSeed, TargetKnowledgeBase
from matcher.model import EvidenceClass, TargetScope
from matcher.query import RecallQuery


class LegacyKnowledgeAdapter(TargetKnowledgeBase):
    """Local-only knowledge inventory. Legacy material is always hint-grade."""
    backend_name = "legacy-local-adapter"

    def __init__(self, delegate: TargetKnowledgeBase) -> None:
        self.delegate = delegate
        self.network_call_count = 0

    def search(self, query: RecallQuery, target_scope: TargetScope, limit: int) -> Sequence[KnowledgeSeed]:
        return self.delegate.search(query, target_scope, limit)

    def get_evidence(self, evidence_ref: str) -> EvidenceItem | None:
        item = self.delegate.get_evidence(evidence_ref)
        if item is None:
            return None
        if item.source_type in {EvidenceClass.RAG_HIT, EvidenceClass.API_CARD, EvidenceClass.RECIPE_HINT, EvidenceClass.LEGACY_HINT, EvidenceClass.FEEDBACK_HINT}:
            return EvidenceItem(**{**item.__dict__, "initial_epistemic_status": "HYPOTHESIS"})
        return item

    def get_symbol(self, symbol_ref: str) -> Mapping[str, Any] | None: return self.delegate.get_symbol(symbol_ref)
    def get_subject(self, subject_ref: str) -> Mapping[str, Any] | None: return self.delegate.get_subject(subject_ref)
    def related_surfaces(self, entity_ref: str) -> Sequence[KnowledgeSeed]: return self.delegate.related_surfaces(entity_ref)
    def find_evidence(self, **kwargs: Any) -> Sequence[EvidenceItem]: return tuple(self.get_evidence(x.evidence_ref) for x in self.delegate.find_evidence(**kwargs) if self.get_evidence(x.evidence_ref) is not None)


class MatcherReentryKnowledgeAdapter(LegacyKnowledgeAdapter):
    """Search-space filter; it never changes Transfer Signature truth."""
    backend_name = "matcher-reentry-filter"

    def __init__(self, delegate: TargetKnowledgeBase, *, excluded_seed_refs: Sequence[str] = (), excluded_candidate_refs: Sequence[str] = ()) -> None:
        super().__init__(delegate)
        self.excluded_seed_refs = frozenset(excluded_seed_refs)
        self.excluded_candidate_refs = frozenset(excluded_candidate_refs)

    def _included(self, seed: KnowledgeSeed) -> bool:
        metadata = dict(seed.metadata)
        return seed.entity_ref not in self.excluded_seed_refs and str(metadata.get("candidate_ref", "")) not in self.excluded_candidate_refs and str(metadata.get("binding_ref", "")) not in self.excluded_candidate_refs

    def search(self, query: RecallQuery, target_scope: TargetScope, limit: int) -> Sequence[KnowledgeSeed]:
        return tuple(seed for seed in self.delegate.search(query, target_scope, limit) if self._included(seed))[:limit]

    def related_surfaces(self, entity_ref: str) -> Sequence[KnowledgeSeed]:
        return tuple(seed for seed in self.delegate.related_surfaces(entity_ref) if self._included(seed))
