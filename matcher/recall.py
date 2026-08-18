"""Wide recall and multi-subject candidate-surface assembly."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from matcher.knowledge import KnowledgeSeed, TargetKnowledgeBase
from matcher.model import (
    AssemblyRecord,
    MatcherCandidate,
    RetrievalRecord,
    TargetScope,
    semantic_digest,
)
from matcher.query import RecallQuery


@dataclass(frozen=True)
class RecallResult:
    seeds: tuple[KnowledgeSeed, ...]
    records: tuple[RetrievalRecord, ...]
    budget_exhausted: bool


def wide_recall(
    knowledge: TargetKnowledgeBase,
    query: RecallQuery,
    target_scope: TargetScope,
    *,
    limit: int,
) -> RecallResult:
    if limit < 1:
        raise ValueError("recall limit must be positive")
    fetched = list(knowledge.search(query, target_scope, limit + 1))
    budget_exhausted = len(fetched) > limit
    seeds = tuple(fetched[:limit])
    records = []
    for rank, seed in enumerate(seeds, start=1):
        record_semantic = {
            "backend": knowledge.backend_name,
            "query_ref": query.query_id,
            "entity_ref": seed.entity_ref,
            "entity_kind": seed.entity_kind,
            "evidence_refs": sorted(seed.evidence_refs),
            "rank": rank,
            "score": seed.score,
            "metadata": deepcopy(dict(seed.metadata)),
        }
        records.append(
            RetrievalRecord(
                retrieval_id="retrieval:" + semantic_digest(record_semantic),
                backend=knowledge.backend_name,
                query_ref=query.query_id,
                entity_ref=seed.entity_ref,
                entity_kind=seed.entity_kind,
                evidence_refs=tuple(sorted(dict.fromkeys(seed.evidence_refs))),
                rank=rank,
                score=seed.score,
                metadata=deepcopy(dict(seed.metadata)),
            )
        )
    return RecallResult(seeds, tuple(records), budget_exhausted)


def assemble_candidate_surfaces(
    recall: RecallResult,
) -> tuple[tuple[MatcherCandidate, ...], tuple[AssemblyRecord, ...]]:
    """Group only explicitly compatible seeds; never merge unrelated surfaces."""

    record_by_entity = {item.entity_ref: item for item in recall.records}
    grouped: dict[tuple[str, str, str, str], list[KnowledgeSeed]] = {}
    for seed in recall.seeds:
        compatibility = str(
            seed.metadata.get("compatibility_group") or seed.target_scope.surface_ref
        )
        key = (
            seed.target_scope.library,
            seed.target_scope.version,
            seed.target_scope.surface_ref,
            compatibility,
        )
        grouped.setdefault(key, []).append(seed)

    candidates: list[MatcherCandidate] = []
    assemblies: list[AssemblyRecord] = []
    for key in sorted(grouped):
        seeds = sorted(grouped[key], key=lambda item: item.entity_ref)
        scope = seeds[0].target_scope
        if any(item.target_scope != scope for item in seeds):
            raise ValueError("FRANKENSTEIN_SURFACE_SCOPE_MISMATCH")

        composition: dict[str, Any] = {
            "surface_kind": _surface_kind(seeds),
            "members": [item.entity_ref for item in seeds],
            "entity_kinds": sorted({item.entity_kind for item in seeds}),
        }
        helper_mappings = None
        assignments: list[Any] = []
        for seed in seeds:
            for name, value in seed.surface_composition.items():
                if name == "_binding_mappings":
                    if helper_mappings is not None and helper_mappings != value:
                        raise ValueError("FRANKENSTEIN_BINDING_MAPPING_CONFLICT")
                    helper_mappings = deepcopy(value)
                elif name == "assignments":
                    assignments.extend(deepcopy(value) if isinstance(value, list) else [deepcopy(value)])
                elif name not in composition:
                    composition[name] = deepcopy(value)
                elif composition[name] != value:
                    raise ValueError(f"INCOMPATIBLE_SURFACE_COMPOSITION:{name}")
        if assignments:
            composition["assignments"] = sorted(
                assignments, key=lambda item: repr(item)
            )
        if helper_mappings is not None:
            composition["_binding_mappings"] = helper_mappings

        relations = tuple(
            relation
            for seed in seeds
            for relation in seed.surface_relations
        )
        candidate_records = tuple(
            record_by_entity[seed.entity_ref]
            for seed in seeds
            if seed.entity_ref in record_by_entity
        )
        candidate = MatcherCandidate.create(
            target_scope=scope,
            subject_refs=[ref for seed in seeds for ref in seed.subject_refs],
            symbol_refs=[ref for seed in seeds for ref in seed.symbol_refs],
            surface_composition=composition,
            surface_relations=relations,
            evidence_refs=[ref for seed in seeds for ref in seed.evidence_refs],
            retrieval_records=candidate_records,
        )
        assembly_semantic = {
            "seed_refs": [item.entity_ref for item in seeds],
            "candidate_ref": candidate.candidate_id,
            "relation_reasons": _relation_reasons(seeds),
        }
        assembly = AssemblyRecord(
            assembly_id="assembly:" + semantic_digest(assembly_semantic),
            seed_refs=tuple(assembly_semantic["seed_refs"]),
            relation_reasons=tuple(assembly_semantic["relation_reasons"]),
            candidate_ref=candidate.candidate_id,
        )
        candidates.append(candidate)
        assemblies.append(assembly)

    candidates.sort(key=lambda item: item.candidate_id)
    assemblies.sort(key=lambda item: item.candidate_ref)
    return tuple(candidates), tuple(assemblies)


def _surface_kind(seeds: Sequence[KnowledgeSeed]) -> str:
    kinds = {item.entity_kind for item in seeds}
    if "STATEFUL_OPERATION_FAMILY" in kinds or len(seeds) > 2:
        return "MULTI_SUBJECT_CALL_SURFACE"
    if len(seeds) > 1:
        return "API_GROUP"
    return next(iter(kinds), "SINGLE_SYMBOL")


def _relation_reasons(seeds: Sequence[KnowledgeSeed]) -> list[str]:
    reasons = {
        str(reason)
        for seed in seeds
        for reason in seed.metadata.get("assembly_reasons", [])
    }
    if len(seeds) > 1:
        reasons.add("EXPLICIT_COMPATIBILITY_GROUP")
    return sorted(reasons)
