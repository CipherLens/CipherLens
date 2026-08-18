"""Merge completion/adaptation routing and the sole v2 ExecutionHandoff gate."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from execution_pipeline.handoff import create_execution_handoff
from template_binding_merge.adaptation import apply_adaptation
from template_binding_merge.completion import programmatic_complete
from template_binding_merge.model import ValidationContext
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.render import render_base_source


class MergeExecutionRejected(ValueError): pass


@dataclass(frozen=True)
class MergeExecutionResult:
    merge: Mapping[str, Any]
    source_bytes: bytes
    source_map: Mapping[str, Any]
    bound_source: Mapping[str, Any]
    validation: Mapping[str, Any]
    handoff: Mapping[str, Any] | None


def _validate(gate: Any, merge: Mapping[str, Any], rendered: Any) -> Mapping[str, Any]:
    return validate_merged_source(ValidationContext(gate, merge, rendered.source_bytes, rendered.source_map, rendered.bound_source))


def prepare_merge_execution(*, contract: Mapping[str, Any], gate: Any, merge: Mapping[str, Any], repo_root: str | Path, adaptation_provider: Callable[[Mapping[str, Any], Any], Mapping[str, Any] | None] | None = None, phase_callback: Callable[[str], None] | None = None) -> MergeExecutionResult:
    """Render, complete/adapt only declared holes, then enforce ExecutionHandoff."""
    rendered = render_base_source(merge, repo_root)
    validation = _validate(gate, merge, rendered)
    routing = validation.get("routing")
    if routing == "PROGRAMMATIC_COMPLETION":
        if phase_callback is not None: phase_callback("COMPLETING")
        rendered = programmatic_complete(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, repo_root)
        validation = _validate(gate, merge, rendered)
        routing = validation.get("routing")
    if routing == "CONSTRAINED_ADAPTATION":
        if phase_callback is not None: phase_callback("ADAPTING")
        if adaptation_provider is None:
            return MergeExecutionResult(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, validation, None)
        proposal = adaptation_provider(merge, rendered)
        if proposal is None:
            return MergeExecutionResult(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, validation, None)
        rendered = apply_adaptation(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, proposal, repo_root)
        validation = _validate(gate, merge, rendered)
        routing = validation.get("routing")
    if routing == "WHOLE_BINDING_SWITCH":
        return MergeExecutionResult(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, validation, None)
    if validation.get("status") != "VALID" or routing != "EXECUTION_HANDOFF":
        raise MergeExecutionRejected("Merge did not reach a valid ExecutionHandoff state")
    handoff = create_execution_handoff(contract, gate.candidate_binding, merge, validation, rendered.bound_source, rendered.source_map, rendered.source_bytes)
    return MergeExecutionResult(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, validation, handoff)
