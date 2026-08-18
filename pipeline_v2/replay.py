"""Replay invokes the current pipeline; old Verdicts are reference metadata only."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from matcher.orchestrate import MatcherRequest
from pipeline_v2.attempt import PipelineAttempt, PipelineAttemptResult
from template_binding_merge.model import TemplateBundle


@dataclass(frozen=True)
class ReplayResult:
    new_attempt: PipelineAttemptResult
    divergence: bool
    reason_code: str | None


def replay_attempt(*, pipeline: PipelineAttempt, attempt_id: str, request: MatcherRequest, bundle: TemplateBundle, prior_attempt_id: str, prior_verdict: Mapping[str, Any] | None = None, adaptation_provider: Any = None, argv: Sequence[str] = ()) -> ReplayResult:
    """Re-enter the full pipeline under a new attempt identity."""
    if not attempt_id or attempt_id == prior_attempt_id:
        raise ValueError("replay requires a new attempt_id")
    current = pipeline.run(attempt_id=attempt_id, request=request, bundle=bundle, adaptation_provider=adaptation_provider, argv=argv)
    old_value = prior_verdict.get("verdict") if prior_verdict else None
    new_value = current.verdict.get("verdict") if current.verdict else None
    changed = old_value is not None and old_value != new_value
    return ReplayResult(current, changed, "REPLAY_DIVERGENCE" if changed else None)
