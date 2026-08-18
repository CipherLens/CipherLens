"""Untrusted proposal envelope and deterministic restricted-edit application."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from template_binding_merge.canonical import (
    bound_source_digest,
    expected_adaptation_proposal_id,
    merge_digest,
    source_map_digest,
)
from template_binding_merge.model import (
    ADAPTATION_SCHEMA_VERSION,
    AdaptationRejected,
    HoleResolver,
)
from template_binding_merge.render import render_base_source
from template_binding_merge.validate import (
    validate_adaptation_proposal_or_raise,
    validate_bound_source_or_raise,
    validate_merge_or_raise,
    validate_source_map_or_raise,
)


def build_adaptation_proposal(
    merge: Mapping[str, Any],
    base_bound_source: Mapping[str, Any],
    restricted_edits: Iterable[Mapping[str, Any]],
    *,
    provider_id: str,
    provider_version: str,
    request_digest: str,
) -> dict[str, Any]:
    """Wrap provider output as PROPOSED evidence, never as trusted source."""

    validate_merge_or_raise(merge)
    validate_bound_source_or_raise(base_bound_source)
    proposal: dict[str, Any] = {
        "schema_version": ADAPTATION_SCHEMA_VERSION,
        "proposal_id": "adaptation-proposal:pending",
        "merge_ref": merge["merge_id"],
        "merge_digest": merge_digest(merge),
        "base_bound_source_ref": base_bound_source["bound_source_id"],
        "base_bound_source_digest": bound_source_digest(base_bound_source),
        "provider_provenance": {
            "provider_id": provider_id,
            "provider_version": provider_version,
            "request_digest": request_digest,
        },
        "epistemic_status": "PROPOSED",
        "restricted_edits": [dict(item) for item in restricted_edits],
    }
    proposal["proposal_id"] = expected_adaptation_proposal_id(proposal)
    validate_adaptation_proposal_or_raise(proposal)
    return proposal


def apply_adaptation(
    merge: Mapping[str, Any],
    base_source_bytes: bytes,
    base_source_map: Mapping[str, Any],
    base_bound_source: Mapping[str, Any],
    proposal: Mapping[str, Any],
    repo_root: str | Path,
) -> Any:
    """Apply exact allowlisted hole replacements by rerendering from trusted inputs."""

    errors = _validate_base_artifacts(merge, base_source_bytes, base_source_map, base_bound_source)
    try:
        validate_adaptation_proposal_or_raise(proposal)
    except ValueError as exc:
        errors.append(str(exc))
    current_merge_digest = merge_digest(merge)
    current_bound_digest = bound_source_digest(base_bound_source)
    if proposal.get("merge_ref") != merge.get("merge_id") or proposal.get("merge_digest") != current_merge_digest:
        errors.append("proposal: Merge ref/digest mismatch")
    if proposal.get("base_bound_source_ref") != base_bound_source.get("bound_source_id"):
        errors.append("proposal: base Bound Source ref mismatch")
    if proposal.get("base_bound_source_digest") != current_bound_digest:
        errors.append("proposal: base Bound Source digest mismatch")

    holes = {hole["hole_id"]: hole for hole in merge["adaptation_holes"]}
    fills = _resolved_fills(merge, base_source_bytes, base_source_map, errors)
    unresolved = set(base_bound_source.get("unresolved_hole_refs", []))
    pending_deterministic = sorted(
        hole["hole_id"] for hole in holes.values()
        if hole["hole_id"] in unresolved
        and hole["required"]
        and hole["resolver"] == HoleResolver.DETERMINISTIC_ONLY.value
    )
    if pending_deterministic:
        errors.append("proposal application must follow deterministic Programmatic Completion")
    proposed_holes = {
        edit.get("hole_ref") for edit in proposal.get("restricted_edits", [])
        if isinstance(edit.get("hole_ref"), str)
    }
    edited_holes: set[str] = set()
    for edit in proposal.get("restricted_edits", []):
        hole_ref = edit.get("hole_ref")
        hole = holes.get(hole_ref)
        if hole is None:
            errors.append(f"edit {edit.get('edit_id')}: undeclared hole")
            continue
        if hole_ref in edited_holes:
            errors.append(f"edit {edit.get('edit_id')}: duplicate edit for hole")
        edited_holes.add(hole_ref)
        if hole["resolver"] != HoleResolver.PROPOSAL_ALLOWED.value:
            errors.append(f"edit {edit.get('edit_id')}: hole is not proposal-resolvable")
        if any(dependency not in fills and dependency not in proposed_holes for dependency in hole["dependencies"]):
            errors.append(f"edit {edit.get('edit_id')}: unresolved hole dependency")
        if edit.get("edit_type") not in hole["allowed_edit_types"]:
            errors.append(f"edit {edit.get('edit_id')}: edit type is not allowlisted")
        if edit.get("base_source_digest") != base_bound_source.get("source_digest"):
            errors.append(f"edit {edit.get('edit_id')}: stale base source digest")
        if edit.get("expected_syntax_kind") != hole["syntax_kind"]:
            errors.append(f"edit {edit.get('edit_id')}: syntax kind mismatch")
        replacement = edit.get("replacement")
        replacement_digest = (
            hashlib.sha256(replacement.encode("utf-8")).hexdigest()
            if isinstance(replacement, str) else None
        )
        if replacement_digest not in hole["allowed_replacement_digests"]:
            errors.append(f"edit {edit.get('edit_id')}: replacement is not exactly allowlisted")
        if isinstance(replacement, str):
            fills[str(hole_ref)] = replacement

    if errors:
        raise AdaptationRejected("AdaptationProposal application", errors)
    return render_base_source(
        merge,
        repo_root,
        source_artifact_ref=base_bound_source["source_artifact_ref"],
        fills=fills,
    )


def _validate_base_artifacts(
    merge: Mapping[str, Any],
    source_bytes: bytes,
    source_map: Mapping[str, Any],
    bound_source: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    for validator, value, label in (
        (validate_merge_or_raise, merge, "Merge"),
        (validate_source_map_or_raise, source_map, "SourceMap"),
        (validate_bound_source_or_raise, bound_source, "Bound Source"),
    ):
        try:
            validator(value)
        except ValueError as exc:
            errors.append(f"{label}: {exc}")
    current_merge_digest = merge_digest(merge)
    if bound_source.get("merge_ref") != merge.get("merge_id") or bound_source.get("merge_digest") != current_merge_digest:
        errors.append("Bound Source: Merge ref/digest mismatch")
    if source_map.get("merge_ref") != merge.get("merge_id") or source_map.get("merge_digest") != current_merge_digest:
        errors.append("SourceMap: Merge ref/digest mismatch")
    if bound_source.get("source_map_ref") != source_map.get("source_map_id"):
        errors.append("Bound Source: SourceMap ref mismatch")
    try:
        actual_map_digest = source_map_digest(source_map)
    except ValueError as exc:
        errors.append(f"SourceMap: canonical digest unavailable ({exc})")
    else:
        if bound_source.get("source_map_digest") != actual_map_digest:
            errors.append("Bound Source: SourceMap digest mismatch")
    if bound_source.get("source_digest") != hashlib.sha256(source_bytes).hexdigest():
        errors.append("Bound Source: source bytes digest mismatch")
    _verify_regions(source_bytes, source_map, errors)
    return errors


def _verify_regions(source_bytes: bytes, source_map: Mapping[str, Any], errors: list[str]) -> None:
    regions = source_map.get("regions", [])
    expected_start = 0
    for region in regions:
        source_range = region.get("source_range", {})
        start, end = source_range.get("byte_start"), source_range.get("byte_end")
        if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end > len(source_bytes) or start > end:
            errors.append(f"region {region.get('region_id')}: range outside source")
            continue
        if start != expected_start:
            errors.append(f"region {region.get('region_id')}: undeclared source gap or overlap")
        expected_start = end
        digest = hashlib.sha256(source_bytes[start:end]).hexdigest()
        if digest != region.get("canonical_digest"):
            errors.append(f"region {region.get('region_id')}: source content digest mismatch")
    if expected_start != len(source_bytes):
        errors.append("SourceMap regions do not exactly cover source bytes")


def _resolved_fills(
    merge: Mapping[str, Any],
    source_bytes: bytes,
    source_map: Mapping[str, Any],
    errors: list[str],
) -> dict[str, str]:
    holes = {hole["hole_id"]: hole for hole in merge["adaptation_holes"]}
    fills: dict[str, str] = {}
    for region in source_map.get("regions", []):
        refs = region.get("adaptation_hole_refs", [])
        if not refs:
            continue
        if len(refs) != 1:
            errors.append(f"region {region.get('region_id')}: adaptation region must bind one hole")
            continue
        hole_ref = refs[0]
        hole = holes.get(hole_ref)
        if hole is None:
            errors.append(f"region {region.get('region_id')}: undeclared hole reference")
            continue
        source_range = region["source_range"]
        payload = source_bytes[source_range["byte_start"]:source_range["byte_end"]]
        sentinel = b"\n" + f"/*__CIPHERLENS_HOLE:{hole_ref}__*/".encode("utf-8") + b"\n"
        if payload == sentinel:
            continue
        if len(payload) < 2 or not payload.startswith(b"\n") or not payload.endswith(b"\n"):
            errors.append(f"region {region.get('region_id')}: noncanonical hole envelope")
            continue
        try:
            replacement = payload[1:-1].decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"region {region.get('region_id')}: replacement is not UTF-8")
            continue
        digest = hashlib.sha256(replacement.encode("utf-8")).hexdigest()
        if digest not in hole["allowed_replacement_digests"]:
            errors.append(f"region {region.get('region_id')}: existing replacement is not allowlisted")
            continue
        fills[hole_ref] = replacement
    return fills
