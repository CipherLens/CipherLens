"""Novelty gate helpers for campaign family selection."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


DEFAULT_PREFERRED_UNTESTED = [
    "pkey_verify_semantic",
    "evp_digest_ctx_lifecycle",
    "evp_cipher_ctx_lifecycle",
    "provider_fetch_lifecycle",
    "ossl_store_lifecycle",
    "ec_arithmetic_semantic",
    "bn_arithmetic_semantic",
]


def historical_tested_families(policy: dict[str, Any]) -> set[str]:
    return set((policy.get("historical_tested_families") or {}).keys())


def policy_known_pattern_only_families(policy: dict[str, Any]) -> set[str]:
    return set((policy.get("known_pattern_only_families") or {}).keys())


def completed_no_candidate_families(policy: dict[str, Any]) -> set[str]:
    return set((policy.get("completed_no_candidate_families") or {}).keys())


def preferred_untested_families(policy: dict[str, Any]) -> list[str]:
    configured = policy.get("preferred_untested_non_parsing_families") or []
    ordered = [str(item) for item in configured if item]
    for family in DEFAULT_PREFERRED_UNTESTED:
        if family not in ordered:
            ordered.append(family)
    return ordered


def novelty_gate_summary(
    *,
    policy: dict[str, Any],
    selected_family: str,
    selected_track: str,
    candidates: list[dict[str, Any]],
    completed_known_pattern_only: list[str],
) -> dict[str, Any]:
    historical = sorted(historical_tested_families(policy))
    policy_known = sorted(policy_known_pattern_only_families(policy))
    completed_no_candidate = sorted(completed_no_candidate_families(policy))
    historical_skipped = sorted(
        str(item.get("family"))
        for item in candidates
        if item.get("status") == "historical_tested_skipped" and item.get("family")
    )
    known_skipped = sorted(
        str(item.get("family"))
        for item in candidates
        if item.get("status") in {"known_pattern_only_skipped", "completed_known_pattern_only_skipped"}
            and item.get("family")
    )
    completed_no_candidate_skipped = sorted(
        str(item.get("family"))
        for item in candidates
        if item.get("status") == "completed_no_candidate_skipped" and item.get("family")
    )
    selected_is_historical = selected_family in historical
    selected_is_known = selected_family in set(policy_known) | set(completed_known_pattern_only)
    selected_is_completed_no_candidate = selected_family in set(completed_no_candidate)
    return {
        "schema": "family_novelty_gate_summary_v1",
        "generated_at": now_iso(),
        "family_novelty_policy_loaded": bool(policy),
        "historical_tested_families_loaded": bool(historical),
        "historical_tested_families": historical,
        "known_pattern_only_families": policy_known,
        "completed_known_pattern_only_families": completed_known_pattern_only,
        "completed_no_candidate_families": completed_no_candidate,
        "historical_tested_skipped_families": historical_skipped,
        "known_pattern_only_skipped_families": known_skipped,
        "completed_no_candidate_skipped_families": completed_no_candidate_skipped,
        "secure_heap_marked_historical_tested": "secure_heap_state_lifecycle" in historical,
        "secure_heap_skipped": "secure_heap_state_lifecycle" in historical_skipped,
        "selected_family": selected_family,
        "selected_track": selected_track,
        "selected_family_is_historical_tested": selected_is_historical,
        "selected_family_is_known_pattern_only": selected_is_known,
        "selected_family_is_completed_no_candidate": selected_is_completed_no_candidate,
        "prefer_untested_non_parsing_family": bool(
            (policy.get("default_selection_policy") or {}).get("prefer_untested_non_parsing_family")
        ),
        "skip_completed_no_candidate": bool(
            (policy.get("default_selection_policy") or {}).get("skip_completed_no_candidate")
        ),
    }
