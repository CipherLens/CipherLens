"""Allowlisted deterministic and idempotent programmatic completion."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

from template_binding_merge.adaptation import _resolved_fills, _validate_base_artifacts
from template_binding_merge.merge import deterministic_hole_replacement
from template_binding_merge.model import AdaptationRejected, HoleResolver
from template_binding_merge.render import render_base_source


def programmatic_complete(
    merge: Mapping[str, Any],
    base_source_bytes: bytes,
    base_source_map: Mapping[str, Any],
    base_bound_source: Mapping[str, Any],
    repo_root: str | Path,
) -> Any:
    """Fill only DETERMINISTIC_ONLY holes having a frozen local recipe."""

    errors = _validate_base_artifacts(merge, base_source_bytes, base_source_map, base_bound_source)
    fills = _resolved_fills(merge, base_source_bytes, base_source_map, errors)
    unresolved = set(base_bound_source.get("unresolved_hole_refs", []))
    pending = {
        hole["hole_id"]: hole for hole in merge["adaptation_holes"]
        if hole["hole_id"] in unresolved and hole["resolver"] == HoleResolver.DETERMINISTIC_ONLY.value
    }
    made_progress = True
    while made_progress:
        made_progress = False
        for hole_id in sorted(list(pending)):
            hole = pending[hole_id]
            if any(dependency not in fills for dependency in hole["dependencies"]):
                continue
            try:
                replacement = deterministic_hole_replacement(hole["hole_type"], hole_id)
            except KeyError:
                del pending[hole_id]
                continue
            digest = hashlib.sha256(replacement.encode("utf-8")).hexdigest()
            if digest not in hole["allowed_replacement_digests"]:
                errors.append(f"hole {hole_id}: deterministic recipe digest is not allowlisted")
                del pending[hole_id]
                continue
            fills[hole_id] = replacement
            del pending[hole_id]
            made_progress = True
    if errors:
        raise AdaptationRejected("Programmatic Completion", errors)
    return render_base_source(
        merge,
        repo_root,
        source_artifact_ref=base_bound_source["source_artifact_ref"],
        fills=fills,
    )
