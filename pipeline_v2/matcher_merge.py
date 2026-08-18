"""Strict Matcher-to-Merge bridge with no legacy semantic authority."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from candidate_binding.canonical import candidate_binding_digest, validation_digest
from matcher.model import MatcherRunOutcome
from matcher.orchestrate import MatcherRequest, MatcherResult, run_matcher
from template_binding_merge.gate import validate_merge_gate
from template_binding_merge.merge import construct_merge
from template_binding_merge.model import TemplateBundle


class MatcherMergeRejected(ValueError): pass


@dataclass(frozen=True)
class MatcherMergeResult:
    matcher: MatcherResult
    merge_gate: Any | None = None
    merge: Mapping[str, Any] | None = None
    excluded_seed_refs: tuple[str, ...] = ()


def _selected_seed_refs(result: MatcherResult) -> tuple[str, ...]:
    attempts = result.trace.semantic_core.get("binding_attempts", [])
    candidate_ref = attempts[-1].get("candidate_ref") if attempts else ""
    records = result.trace.semantic_core.get("candidate_records", [])
    selected = next((item for item in records if item.get("candidate_id") == candidate_ref), {})
    composition = selected.get("surface_composition", {})
    return tuple(sorted(str(x) for x in composition.get("members", []) if isinstance(x, str)))


def match_then_merge(request: MatcherRequest, bundle: TemplateBundle) -> MatcherMergeResult:
    result = run_matcher(request)
    if result.outcome is not MatcherRunOutcome.MATCH_FOUND:
        return MatcherMergeResult(result)
    binding, validation = result.candidate_binding, result.candidate_binding_validation
    if binding is None or validation is None or validation.get("status") != "VALID":
        raise MatcherMergeRejected("MATCH_FOUND requires a VALID CandidateBinding")
    if result.trace.semantic_core.get("selected_binding_ref") != binding.get("binding_id") or result.trace.semantic_core.get("selected_binding_digest") != candidate_binding_digest(binding) or result.trace.semantic_core.get("selected_validation_ref") != validation.get("validation_id") or result.trace.semantic_core.get("selected_validation_digest") != validation_digest(validation):
        raise MatcherMergeRejected("Matcher selected refs/digests do not match current binding")
    gate = validate_merge_gate(bundle, request.template_manifest, binding, validation, request.repo_root, expected_target_scope=request.target_scope.to_dict())
    return MatcherMergeResult(result, gate, construct_merge(gate), _selected_seed_refs(result))
