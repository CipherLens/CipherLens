"""Immutable operational events and non-authoritative attempt manifests."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from pipeline_v2.artifact_store import ArtifactRef
from pipeline_v2.model import AttemptEventType


_FORBIDDEN = frozenset({"verdict", "safe", "library_safe", "library_verdict", "vulnerability_confirmed"})


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(child) for child in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw(child) for child in value]
    return value


@dataclass(frozen=True)
class AttemptEvent:
    sequence: int
    event_type: AttemptEventType
    reason_code: str = ""
    artifacts: tuple[ArtifactRef, ...] = ()
    state: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "event_type": self.event_type.value, "reason_code": self.reason_code, "artifacts": [x.to_dict() for x in self.artifacts], "state": _thaw(self.state)}


class AttemptEventLog:
    def __init__(self, attempt_id: str) -> None:
        self.attempt_id = attempt_id
        self._events: list[AttemptEvent] = []
        self._closed = False

    def append(self, event_type: AttemptEventType, *, reason_code: str = "", artifacts: Sequence[ArtifactRef] = (), state: Mapping[str, Any] | None = None) -> AttemptEvent:
        if self._closed:
            raise RuntimeError("attempt event log is closed")
        event = AttemptEvent(len(self._events) + 1, event_type, reason_code, tuple(artifacts), _freeze(state or {}))
        self._events.append(event)
        return event

    def close(self) -> None:
        self._closed = True

    @property
    def events(self) -> tuple[AttemptEvent, ...]:
        return tuple(self._events)


def build_attempt_manifest(*, attempt_id: str, events: Sequence[AttemptEvent], artifact_refs: Mapping[str, ArtifactRef], outcome: str, reproduction_ref: ArtifactRef | None = None) -> dict[str, Any]:
    if not events or events[-1].event_type is not AttemptEventType.CLOSED:
        raise ValueError("final manifest requires a CLOSED immutable event stream")
    if _FORBIDDEN & set(artifact_refs):
        raise ValueError("attempt manifest must not own a security verdict")
    result = {"schema_version": "cipherlens.campaign_attempt_manifest.v0.1", "attempt_id": attempt_id, "events": [x.to_dict() for x in events], "artifacts": {key: value.to_dict() for key, value in sorted(artifact_refs.items())}, "outcome": outcome}
    if reproduction_ref is not None:
        result["reproduction_manifest"] = reproduction_ref.to_dict()
    return result


def build_reproduction_manifest(*, attempt_id: str, artifacts: Mapping[str, ArtifactRef], target_scope: Mapping[str, Any], repo_revision: str, repo_tree_digest: str, toolchain_profile: Mapping[str, Any], execution_config: Mapping[str, Any]) -> dict[str, Any]:
    return {"schema_version": "cipherlens.attempt_reproduction_manifest.v0.1", "attempt_id": attempt_id, "target_scope": dict(target_scope), "repo_revision": repo_revision, "repo_tree_digest": repo_tree_digest, "toolchain_profile": dict(toolchain_profile), "execution_config": dict(execution_config), "artifacts": {key: value.to_dict() for key, value in sorted(artifacts.items())}}
