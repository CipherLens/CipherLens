"""Track diversification helpers for campaign family selection."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso
from analysis.family_novelty_gate import (
    historical_tested_families,
    policy_known_pattern_only_families,
    preferred_untested_families,
)


NON_PARSING_TRACK_ORDER = ["lifecycle", "semantic", "state"]


def family_track(family: str, policy: dict[str, Any], profiles: dict[str, Any]) -> str:
    profile = (profiles.get("families") or {}).get(family) or {}
    if profile.get("track"):
        return str(profile["track"])
    for track, cfg in (policy.get("tracks") or {}).items():
        if family in (cfg.get("families") or []):
            return str(track)
    if family.endswith("_parsing") or family in {"cms_container_parsing"}:
        return "parsing"
    return "unknown"


def parsing_known_pattern_seen(previous_gate: dict[str, Any], completed_families: set[str]) -> bool:
    return bool(
        completed_families
        or (
            previous_gate.get("known_pattern_repeat_deduplicated")
            and previous_gate.get("stop_campaign") is False
            and not previous_gate.get("new_candidates")
        )
    )


def select_diversified_family(
    *,
    profiles: dict[str, Any],
    policy: dict[str, Any],
    novelty_policy: dict[str, Any] | None = None,
    skipped_families: set[str],
    completed_families: set[str],
    previous_gate: dict[str, Any],
) -> dict[str, Any]:
    novelty_policy = novelty_policy or {}
    profile_names = set((profiles.get("families") or {}).keys())
    known_seen = parsing_known_pattern_seen(previous_gate, completed_families)
    historical_tested = historical_tested_families(novelty_policy)
    policy_known_only = policy_known_pattern_only_families(novelty_policy)
    all_known_only = set(completed_families) | policy_known_only
    rows = []
    ordered_names = []
    for family in preferred_untested_families(novelty_policy) + sorted(profile_names):
        if family in profile_names and family not in ordered_names:
            ordered_names.append(family)
    for family in ordered_names:
        track = family_track(family, policy, profiles)
        status = "ready"
        reason = "profile_ready"
        if family in skipped_families:
            status = "external_pending_skipped"
            reason = "family is external pending"
        elif family in historical_tested:
            status = "historical_tested_skipped"
            reason = "family already manually reproduced or historically tested"
        elif family in all_known_only:
            status = "completed_known_pattern_only_skipped"
            reason = "family completed with known-pattern-only candidates"
        elif known_seen and track == "parsing":
            status = "parsing_track_deprioritized"
            reason = "parsing track already hit known DER trailing-garbage full-consumption pattern"
        rows.append({"family": family, "track": track, "status": status, "reason": reason})

    ready = [item for item in rows if item["status"] == "ready"]
    non_parsing_ready = [item for item in ready if item["track"] != "parsing"]
    selected = {}
    for track in NON_PARSING_TRACK_ORDER:
        selected = next((item for item in non_parsing_ready if item["track"] == track), {})
        if selected:
            break
    if not selected and not known_seen:
        selected = ready[0] if ready else {}
    return {
        "schema": "track_selection_summary_v1",
        "generated_at": now_iso(),
        "family_track_policy_loaded": bool(policy.get("tracks")),
        "family_novelty_policy_loaded": bool(novelty_policy),
        "known_pattern_history_loaded": bool(previous_gate),
        "historical_tested_families_loaded": bool(historical_tested),
        "parsing_known_pattern_seen": known_seen,
        "parsing_track_deprioritized": known_seen,
        "non_parsing_track_prioritized": bool(known_seen and non_parsing_ready),
        "selected_family": selected.get("family", ""),
        "selected_track": selected.get("track", ""),
        "selected_family_is_parsing": selected.get("track") == "parsing",
        "selected_family_is_historical_tested": selected.get("family") in historical_tested,
        "selected_family_is_known_pattern_only": selected.get("family") in all_known_only,
        "no_ready_non_parsing_family": bool(known_seen and not non_parsing_ready),
        "candidates": rows,
    }
