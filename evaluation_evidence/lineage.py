"""Ref/digest lineage helpers used by all evidence records."""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping

from evaluation_evidence.canonical import raw_digest
from evaluation_evidence.model import ArtifactLink


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


def link_for_bytes(ref: str, payload: bytes) -> ArtifactLink:
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("artifact ref must be non-empty")
    return ArtifactLink(ref=ref, digest=raw_digest(payload))


def validate_link(link: Mapping[str, Any], path: str = "link") -> list[str]:
    errors: list[str] = []
    if not isinstance(link, Mapping):
        return [f"{path}: expected object"]
    missing = {"ref", "digest"} - set(link)
    extra = set(link) - {"ref", "digest"}
    errors.extend(f"{path}.{key}: required field missing" for key in sorted(missing))
    errors.extend(f"{path}.{key}: unknown field" for key in sorted(extra))
    if not isinstance(link.get("ref"), str) or not link.get("ref"):
        errors.append(f"{path}.ref: expected non-empty string")
    if not isinstance(link.get("digest"), str) or not SHA256_RE.fullmatch(str(link.get("digest") or "")):
        errors.append(f"{path}.digest: expected lowercase sha256")
    return errors


def verify_link(link: Mapping[str, Any], resolver: Callable[[str, str], bool]) -> bool:
    if validate_link(link):
        return False
    return bool(resolver(str(link["ref"]), str(link["digest"])))
