"""Read-only adapter for research console consumers."""

from __future__ import annotations

import json
from typing import Any, Mapping

from pipeline_v2.artifact_store import ArtifactStore


class CanonicalConsoleAdapter:
    def __init__(self, store: ArtifactStore) -> None: self.store = store

    def artifact(self, ref: str, digest: str) -> bytes:
        return self.store.get(ref, digest)

    def json_artifact(self, ref: str, digest: str) -> Mapping[str, Any]:
        return json.loads(self.artifact(ref, digest).decode("utf-8"))

    def attempt(self, manifest_ref: str, digest: str) -> Mapping[str, Any]:
        return self.json_artifact(manifest_ref, digest)

    def legacy_display_label(self, label: str) -> Mapping[str, str]:
        return {"label": label, "authority": "legacy_display_only"}
