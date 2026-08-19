"""A concrete local backend that exposes only materialized, usable profiles."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from matcher.knowledge import EvidenceItem, KnowledgeSeed, TargetKnowledgeBase
from matcher.model import EvidenceClass, TargetScope
from matcher.query import RecallQuery


class LocalTargetKnowledgeBackend(TargetKnowledgeBase):
    """TargetKnowledgeBase adapter; unverified cards remain retrieval-only evidence."""

    def __init__(self, profiles: Iterable[Mapping[str, Any]] = ()) -> None:
        self._profiles = {str(profile["profile_id"]): dict(profile) for profile in profiles}

    @staticmethod
    def _scope(profile: Mapping[str, Any]) -> TargetScope:
        scope = profile["target_scope"]
        return TargetScope(library=str(scope["library"]), version=str(scope["version"]), surface_ref=str(scope["surface_ref"]))

    def _evidence(self, profile: Mapping[str, Any], query: str) -> list[EvidenceItem]:
        items = []
        for index, record in enumerate(profile.get("evidence_records", [])):
            if query.lower() not in str(record).lower():
                continue
            kind = EvidenceClass.HEADER if record.get("evidence_type") == "HEADER_SIGNATURE" else EvidenceClass.SOURCE
            if record.get("verification_status") != "VERIFIED":
                kind = EvidenceClass.API_CARD
            items.append(EvidenceItem(
                evidence_ref=f"{profile['profile_id']}:evidence:{index}", source_type=kind, target_scope=self._scope(profile),
                subject_refs=(str(profile["target_scope"]["surface_ref"]),), symbol_refs=((str(record["symbol"]),) if record.get("symbol") else ()),
                artifact_ref=str(record.get("file_ref", record.get("card_ref", "target_knowledge"))), artifact_digest=str(record.get("file_digest", record.get("snippet_digest", "candidate"))),
                initial_epistemic_status=str(record.get("verification_status", "CANDIDATE")), metadata=dict(record),
            ))
        return items

    def search(self, query: RecallQuery, target_scope: TargetScope, limit: int) -> list[KnowledgeSeed]:
        results = []
        for profile in self._profiles.values():
            # PREPARED profiles may contribute evidence to matching; only
            # NOT_READY profiles (for example blocked wolfSSL cards) are
            # excluded. This does not make them execution-ready.
            if profile.get("validation_status") == "NOT_READY" or self._scope(profile) != target_scope:
                continue
            evidence = self._evidence(profile, str(query))
            if evidence:
                results.append(KnowledgeSeed(entity_ref=str(profile["profile_id"]), entity_kind="target_profile", target_scope=self._scope(profile), subject_refs=(str(profile["target_scope"]["surface_ref"]),), symbol_refs=tuple(str(item["symbol"]) for item in profile.get("symbol_records", [])), evidence_refs=tuple(item.evidence_ref for item in evidence[:limit]), score=1.0))
        return results[:limit]

    def get_evidence(self, evidence_ref: str) -> EvidenceItem | None:
        profile_id = evidence_ref.split(":evidence:", 1)[0]
        profile = self._profiles.get(profile_id)
        if not profile:
            return None
        suffix = evidence_ref.rsplit(":", 1)[-1]
        try:
            record = profile["evidence_records"][int(suffix)]
        except (ValueError, IndexError):
            return None
        kind = EvidenceClass.HEADER if record.get("evidence_type") == "HEADER_SIGNATURE" else EvidenceClass.SOURCE
        if record.get("verification_status") != "VERIFIED":
            kind = EvidenceClass.API_CARD
        return EvidenceItem(evidence_ref=evidence_ref, source_type=kind, target_scope=self._scope(profile), subject_refs=(str(profile["target_scope"]["surface_ref"]),), symbol_refs=((str(record["symbol"]),) if record.get("symbol") else ()), artifact_ref=str(record.get("file_ref", record.get("card_ref", "target_knowledge"))), artifact_digest=str(record.get("file_digest", record.get("snippet_digest", "candidate"))), initial_epistemic_status=str(record.get("verification_status", "CANDIDATE")), metadata=dict(record))

    def get_symbol(self, symbol_ref: str) -> Mapping[str, Any] | None:
        for profile in self._profiles.values():
            for record in profile.get("symbol_records", []):
                if record.get("symbol") == symbol_ref:
                    return dict(record)
        return None

    def get_subject(self, subject_ref: str) -> Mapping[str, Any] | None:
        for profile in self._profiles.values():
            if profile["target_scope"].get("surface_ref") == subject_ref:
                return dict(profile["target_scope"])
        return None

    def related_surfaces(self, entity_ref: str) -> tuple[KnowledgeSeed, ...]:
        del entity_ref
        return ()

    def find_evidence(self, *, target_scope: TargetScope, subject_ref: str | None = None, symbol_ref: str | None = None, source_types: tuple[EvidenceClass, ...] = ()) -> tuple[EvidenceItem, ...]:
        result = []
        for profile in self._profiles.values():
            if self._scope(profile) != target_scope:
                continue
            for item in self._evidence(profile, symbol_ref or subject_ref or ""):
                if source_types and item.source_type not in set(source_types):
                    continue
                if subject_ref and subject_ref not in item.subject_refs:
                    continue
                if symbol_ref and symbol_ref not in item.symbol_refs:
                    continue
                result.append(item)
        return tuple(sorted(result, key=lambda item: item.evidence_ref))
