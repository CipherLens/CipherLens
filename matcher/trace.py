"""Canonical semantic MatcherTrace and non-canonical telemetry boundary."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from matcher.model import MATCHER_TRACE_SCHEMA_VERSION, canonical_json_bytes, semantic_digest


@dataclass(frozen=True)
class MatcherTrace:
    semantic_core: Mapping[str, Any]

    @property
    def trace_id(self) -> str:
        return str(self.semantic_core["trace_id"])

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.semantic_core)

    def digest(self) -> str:
        return semantic_digest(self.semantic_core)


def matcher_trace_digest(trace: MatcherTrace | Mapping[str, Any]) -> str:
    value = trace.semantic_core if isinstance(trace, MatcherTrace) else trace
    return semantic_digest(value)


class MatcherTraceBuilder:
    def __init__(
        self,
        *,
        source_references: Mapping[str, Any],
        target_scope: Mapping[str, Any],
        recall_query_ref: str,
        recall_query_digest: str,
        retrieval_config: Mapping[str, Any],
    ) -> None:
        self.core: dict[str, Any] = {
            "schema_version": MATCHER_TRACE_SCHEMA_VERSION,
            "source_references": deepcopy(dict(source_references)),
            "target_scope": deepcopy(dict(target_scope)),
            "recall_query_ref": recall_query_ref,
            "recall_query_digest": recall_query_digest,
            "retrieval_config": deepcopy(dict(retrieval_config)),
            "retrieval_records": [],
            "candidate_records": [],
            "assembly_records": [],
            "provider_attempts": [],
            "proposal_records": [],
            "fact_resolution_records": [],
            "profile_records": [],
            "eligibility_records": [],
            "observability_records": [],
            "ranking_records": [],
            "binding_attempts": [],
            "validation_records": [],
            "rejection_records": [],
            "selected_binding_ref": None,
            "selected_binding_digest": None,
            "selected_validation_ref": None,
            "selected_validation_digest": None,
            "run_outcome": None,
            "reason_codes": [],
        }

    def extend(self, field: str, values: Sequence[Mapping[str, Any]]) -> None:
        self.core[field].extend(deepcopy([dict(x) for x in values]))

    def add(self, field: str, value: Mapping[str, Any]) -> None:
        self.core[field].append(deepcopy(dict(value)))

    def finish(
        self,
        *,
        outcome: str,
        reason_codes: Sequence[str],
        selected_binding_ref: str | None = None,
        selected_binding_digest: str | None = None,
        selected_validation_ref: str | None = None,
        selected_validation_digest: str | None = None,
    ) -> MatcherTrace:
        self.core["run_outcome"] = outcome
        self.core["reason_codes"] = sorted(dict.fromkeys(reason_codes))
        self.core["selected_binding_ref"] = selected_binding_ref
        self.core["selected_binding_digest"] = selected_binding_digest
        self.core["selected_validation_ref"] = selected_validation_ref
        self.core["selected_validation_digest"] = selected_validation_digest
        for field, value in self.core.items():
            if isinstance(value, list):
                value.sort(key=lambda item: canonical_json_bytes(item))
        semantic_without_id = deepcopy(self.core)
        semantic_without_id.pop("trace_id", None)
        self.core["trace_id"] = "matcher-trace:" + semantic_digest(semantic_without_id)
        return MatcherTrace(deepcopy(self.core))
