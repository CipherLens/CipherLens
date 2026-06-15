"""Known semantic-pattern gate helpers for campaign stop policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso


KNOWN_PATTERN_ID = "der_single_object_trailing_garbage_full_consumption"


def default_gate() -> dict[str, Any]:
    return {
        "schema": "known_pattern_gate_v1",
        "patterns": [
            {
                "pattern_id": KNOWN_PATTERN_ID,
                "status": "known_semantic_family_candidate",
                "families_observed": ["x509_parsing", "pkey_parsing", "pkcs8_parsing"],
                "families_pending": ["pkcs_container_parsing", "cms_container_parsing"],
                "description": (
                    "Valid DER single object plus trailing garbage is accepted by parser/app path "
                    "while full_consumption is false."
                ),
                "default_action": "deduplicate_and_external_pending",
                "stop_campaign_on_repeat": False,
                "stop_campaign_on_new_family": False,
                "stop_campaign_on_crash_or_sanitizer": True,
                "stop_campaign_on_new_semantic_class": True,
                "claim_policy": {
                    "confirmed_vulnerability": False,
                    "cve": False,
                    "exploitable": False,
                },
            }
        ],
    }


def campaign_stop_policy() -> dict[str, Any]:
    return {
        "schema": "campaign_stop_policy_v1",
        "known_pattern_gate": KNOWN_PATTERN_ID,
        "stop_on_repeat_known_full_consumption_gap": False,
        "stop_on_crash_candidate": True,
        "stop_on_sanitizer_candidate": True,
        "stop_on_new_semantic_class": True,
        "stop_on_new_container_specific_behavior": True,
        "main_feedback_write": False,
        "claim_policy": {
            "confirmed_vulnerability": False,
            "cve": False,
            "exploitable": False,
        },
    }


def ensure_known_pattern_gate(repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    gate_path = repo_root / "config/known_pattern_gate.yaml"
    policy_path = repo_root / "config/campaign_stop_policy.yaml"
    gate = load_yaml(gate_path) or default_gate()
    if not gate.get("patterns"):
        gate = default_gate()
    policy = load_yaml(policy_path) or campaign_stop_policy()
    dump_yaml(gate_path, gate)
    dump_yaml(policy_path, policy)
    return gate, policy


def dedup_policy(gate: dict[str, Any]) -> dict[str, Any]:
    pattern = (gate.get("patterns") or [default_gate()["patterns"][0]])[0]
    return {
        "schema": "known_pattern_dedup_policy_v1",
        "generated_at": now_iso(),
        "pattern_id": pattern.get("pattern_id", KNOWN_PATTERN_ID),
        "repeat_candidate_action": "deduplicate_and_external_pending",
        "stop_campaign_on_repeat": bool(pattern.get("stop_campaign_on_repeat")),
        "stop_campaign_on_crash_or_sanitizer": bool(pattern.get("stop_campaign_on_crash_or_sanitizer")),
        "stop_campaign_on_new_semantic_class": bool(pattern.get("stop_campaign_on_new_semantic_class")),
        "claim_policy": pattern.get("claim_policy", {}),
    }


def family_summary(gate: dict[str, Any]) -> dict[str, Any]:
    pattern = (gate.get("patterns") or [default_gate()["patterns"][0]])[0]
    return {
        "schema": "der_trailing_garbage_family_summary_v1",
        "generated_at": now_iso(),
        "pattern_id": pattern.get("pattern_id", KNOWN_PATTERN_ID),
        "status": pattern.get("status", "known_semantic_family_candidate"),
        "families_observed": pattern.get("families_observed", []),
        "families_pending": pattern.get("families_pending", []),
        "default_action": pattern.get("default_action", ""),
        "confirmed_vulnerability_claim": False,
    }
