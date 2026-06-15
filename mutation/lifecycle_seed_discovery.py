"""Generate lifecycle seed manifests from family profiles.

The module is a generic seed-discovery entrypoint for lifecycle families. The
current implemented archetype is EVP digest context lifecycle, expressed as
structured API sequences instead of rendered C harnesses.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from analysis.family_novelty_gate import completed_no_candidate_families, novelty_gate_summary
from mutation.family_profile_loader import family_profile, load_family_profiles


TASK = "evp_digest_ctx_lifecycle_seed_discovery_v1"
DEFAULT_FAMILY = "evp_digest_ctx_lifecycle"
DEFAULT_FAMILY_PROFILES = "config/family_profiles.yaml"
DEFAULT_NOVELTY_POLICY = "config/family_novelty_policy.yaml"
DEFAULT_PREVIOUS = "artifacts/sprints/pkey_verify_semantic_compile_run_analyze_v1"
DEFAULT_OUT_DIR = f"artifacts/sprints/{TASK}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--family", default=DEFAULT_FAMILY)
    parser.add_argument("--family-profiles", default=DEFAULT_FAMILY_PROFILES)
    parser.add_argument("--novelty-policy", default=DEFAULT_NOVELTY_POLICY)
    parser.add_argument("--previous-family-root", default=DEFAULT_PREVIOUS)
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    return parser.parse_args()


def previous_family_snapshot(previous_root: Path) -> dict[str, Any]:
    qc_path = previous_root / "validation/pkey_verify_semantic_compile_run_analyze_quality_checks.yaml"
    candidate_summary_path = previous_root / "candidate_queue/candidate_summary.yaml"
    qc = load_yaml(qc_path)
    candidate_summary = load_yaml(candidate_summary_path)
    completed = (
        qc.get("family") == "pkey_verify_semantic"
        and qc.get("quality_status") == "pass_no_candidate"
        and int(qc.get("candidate_count") or 0) == 0
    )
    return {
        "schema": "previous_family_snapshot_v1",
        "generated_at": now_iso(),
        "family": qc.get("family", "pkey_verify_semantic"),
        "source_root": previous_root.as_posix(),
        "quality_status": qc.get("quality_status", ""),
        "candidate_count": int(qc.get("candidate_count") or candidate_summary.get("candidate_count") or 0),
        "status": "completed_no_candidate" if completed else "not_completed_no_candidate",
        "completed_no_candidate": completed,
        "skip_on_next_selection": completed,
        "evidence_paths": {
            "quality_checks": qc_path.as_posix(),
            "candidate_summary": candidate_summary_path.as_posix(),
        },
    }


def build_novelty_snapshot(policy: dict[str, Any], selected_family: str, selected_track: str) -> dict[str, Any]:
    candidates = [
        {
            "family": "pkey_verify_semantic",
            "track": "semantic",
            "status": "completed_no_candidate_skipped",
            "reason": "previous pkey_verify_semantic compile/run/analyze completed with no candidates",
        },
        {
            "family": selected_family,
            "track": selected_track,
            "status": "selected_untested_non_parsing",
            "reason": "preferred untested lifecycle family",
        },
    ]
    summary = novelty_gate_summary(
        policy=policy,
        selected_family=selected_family,
        selected_track=selected_track,
        candidates=candidates,
        completed_known_pattern_only=[],
    )
    return {
        **summary,
        "selected_family": selected_family,
        "selected_track": selected_track,
        "candidate_rows": candidates,
        "previous_family_skipped": "pkey_verify_semantic" in completed_no_candidate_families(policy),
    }


def lifecycle_api_card_lookup(repo_root: Path, family: str) -> dict[str, Any]:
    family_card_path = repo_root / f"knowledge/family_cards/{family}.yaml"
    family_card = load_yaml(family_card_path)
    cards = []
    if family_card:
        cards.append(
            {
                "source_path": family_card_path.relative_to(repo_root).as_posix(),
                "type": "family_card",
                "family": family_card.get("family", family),
                "track": family_card.get("track", ""),
                "primary_apis": family_card.get("primary_apis", []) or [],
                "oracle": family_card.get("oracle", []) or [],
            }
        )
    return {
        "schema": "lifecycle_api_card_lookup_v1",
        "generated_at": now_iso(),
        "family": family,
        "lookup_executed": True,
        "api_cards_used": [item["source_path"] for item in cards],
        "cards": cards,
        "selection_reason": (
            "EVP_MD_CTX lifecycle can be represented as structured API sequences "
            "without parser replay, DER trailing garbage, or full-consumption checks."
        ),
    }


def seed_record(
    *,
    seed_id: str,
    seed_type: str,
    api_sequence: list[str],
    expected_behavior: str,
    oracle: list[str],
    enabled: bool,
    mutation_hints: list[str],
    notes: str = "",
    disabled_reason: str = "",
    render_cleanup: list[str] | None = None,
) -> dict[str, Any]:
    record = {
        "seed_id": seed_id,
        "seed_type": seed_type,
        "api_sequence": api_sequence,
        "expected_behavior": expected_behavior,
        "oracle": oracle,
        "enabled": enabled,
        "mutation_hints": mutation_hints,
        "render_requirements": {
            "render_mode": "lifecycle_harness",
            "target_header": "openssl/evp.h",
            "observe_return_codes": True,
            "observe_digest_output_length": True,
            "must_not_use_der_parsing": True,
            "must_not_use_trailing_garbage": True,
            "must_not_use_full_consumption_oracle": True,
            "cleanup": render_cleanup or ["EVP_MD_CTX_free"],
        },
    }
    if notes:
        record["notes"] = notes
    if disabled_reason:
        record["disabled_reason"] = disabled_reason
    return record


def evp_digest_ctx_lifecycle_seeds() -> list[dict[str, Any]]:
    message = "message, message_len"
    out = "digest_out, &digest_out_len"
    return [
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_valid_init_update_final_control",
            seed_type="valid_digest_lifecycle_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                f"EVP_DigestUpdate(ctx, {message})",
                f"EVP_DigestFinal_ex(ctx, {out})",
                "EVP_MD_CTX_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["valid init/update/final control", "digest output length observation"],
        ),
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_update_before_init_control",
            seed_type="invalid_state_update_before_init_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                f"EVP_DigestUpdate(ctx, {message})",
                "EVP_MD_CTX_free",
            ],
            expected_behavior="error_or_reject",
            oracle=["unexpected_success_after_invalid_state", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["call update before digest init", "invalid state return-code observation"],
        ),
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_final_without_update_control",
            seed_type="final_without_update_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                f"EVP_DigestFinal_ex(ctx, {out})",
                "EVP_MD_CTX_free",
            ],
            expected_behavior="success_or_error_documented",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["empty message digest observation", "documented final-without-update boundary"],
            notes="Empty-message digest can be valid; success alone must not be treated as a vulnerability.",
        ),
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_update_after_final_control",
            seed_type="update_after_final_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                f"EVP_DigestUpdate(ctx, {message})",
                f"EVP_DigestFinal_ex(ctx, {out})",
                f"EVP_DigestUpdate(ctx, {message})",
                "EVP_MD_CTX_free",
            ],
            expected_behavior="error_or_documented_behavior",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["post-final update boundary", "state transition observation"],
            notes="API-contract boundary; do not claim a vulnerability from success alone.",
        ),
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_reset_reuse_control",
            seed_type="reset_reuse_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                f"EVP_DigestUpdate(ctx, {message})",
                f"EVP_DigestFinal_ex(ctx, {out})",
                "EVP_MD_CTX_reset",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                f"EVP_DigestUpdate(ctx, {message})",
                f"EVP_DigestFinal_ex(ctx, {out})",
                "EVP_MD_CTX_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["reset and reuse", "second digest output length observation"],
        ),
        seed_record(
            seed_id="evp_digest_ctx_lifecycle_use_after_free_negative_control",
            seed_type="unsafe_negative_control",
            api_sequence=[
                "EVP_MD_CTX_new",
                "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
                "EVP_MD_CTX_free",
                "EVP_DigestUpdate(ctx, message, message_len)",
            ],
            expected_behavior="skip_or_disabled_by_default",
            oracle=["disabled_unsafe_control"],
            enabled=False,
            mutation_hints=["unsafe use-after-free negative control retained only as disabled metadata"],
            disabled_reason=(
                "Use-after-free is intentionally invalid memory use and must not be run by default "
                "as a normal campaign case."
            ),
        ),
    ]


def evp_cipher_ctx_lifecycle_seeds() -> list[dict[str, Any]]:
    message = "plaintext, plaintext_len"
    out = "ciphertext, &ciphertext_len"
    cleanup = ["EVP_CIPHER_CTX_free"]
    return [
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_valid_init_update_final_control",
            seed_type="valid_cipher_lifecycle_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["valid encrypt init/update/final control", "ciphertext length observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_update_before_init_control",
            seed_type="invalid_state_update_before_init_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="error_or_documented",
            oracle=["unexpected_success_after_invalid_state", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["call encrypt update before cipher init", "invalid state return-code observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_final_without_update_control",
            seed_type="final_without_update_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                "EVP_EncryptFinal_ex(ctx, ciphertext, &final_len)",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["padding-only final observation", "documented final-without-update boundary"],
            notes="Final without update may be documented behavior; observe only.",
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_update_after_final_control",
            seed_type="update_after_final_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["post-final update boundary", "state transition observation"],
            notes="Post-final update is observed only; success alone is not a vulnerability.",
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_reset_reuse_control",
            seed_type="reset_reuse_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                "EVP_CIPHER_CTX_reset",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["reset and reuse", "second encrypt output length observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_reinit_without_reset_control",
            seed_type="reinit_without_reset_observation",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
                f"EVP_EncryptUpdate(ctx, {out}, {message})",
                "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
                "EVP_CIPHER_CTX_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["re-init without reset observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="evp_cipher_ctx_lifecycle_use_after_free_negative_control",
            seed_type="unsafe_negative_control",
            api_sequence=[
                "EVP_CIPHER_CTX_new",
                "EVP_CIPHER_CTX_free",
                "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            ],
            expected_behavior="skip_or_disabled_by_default",
            oracle=["disabled_unsafe_control"],
            enabled=False,
            mutation_hints=["unsafe use-after-free negative control retained only as disabled metadata"],
            disabled_reason=(
                "Use-after-free is intentionally invalid memory use and must not be run by default "
                "as a normal campaign case."
            ),
            render_cleanup=cleanup,
        ),
    ]


def mac_lifecycle_seeds() -> list[dict[str, Any]]:
    message = "message, message_len"
    out = "mac_out, &mac_out_len, sizeof(mac_out)"
    cleanup = ["EVP_MAC_CTX_free", "EVP_MAC_free"]
    return [
        seed_record(
            seed_id="mac_lifecycle_valid_hmac_init_update_final_control",
            seed_type="valid_hmac_lifecycle_control",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                'OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0)',
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_update(ctx, {message})",
                f"EVP_MAC_final(ctx, {out})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["valid HMAC init/update/final control", "MAC output length observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_update_before_init_control",
            seed_type="invalid_state_update_before_init_control",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                f"EVP_MAC_update(ctx, {message})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="error_or_documented",
            oracle=["unexpected_success_after_invalid_state", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["call update before MAC init", "invalid state return-code observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_final_without_update_after_init_control",
            seed_type="final_without_update_after_init_observation",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                'OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0)',
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_final(ctx, {out})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["empty-message HMAC final observation"],
            notes="HMAC final after init with no update may be documented success; observe only.",
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_repeated_final_observation_control",
            seed_type="repeated_final_observation",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                'OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0)',
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_update(ctx, {message})",
                f"EVP_MAC_final(ctx, {out})",
                f"EVP_MAC_final(ctx, {out})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["repeated final boundary", "state transition observation"],
            notes="Repeated final is observed only; success alone is not a vulnerability.",
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_update_after_final_observation_control",
            seed_type="update_after_final_observation",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                'OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0)',
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_update(ctx, {message})",
                f"EVP_MAC_final(ctx, {out})",
                f"EVP_MAC_update(ctx, {message})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="observation",
            oracle=["state_transition_observation", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["post-final update boundary", "state transition observation"],
            notes="Post-final update is observed only; success alone is not a vulnerability.",
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_reinit_reuse_control",
            seed_type="reinit_reuse_control",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                'OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0)',
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_update(ctx, {message})",
                f"EVP_MAC_final(ctx, {out})",
                "EVP_MAC_init(ctx, key, key_len, params)",
                f"EVP_MAC_update(ctx, {message})",
                f"EVP_MAC_final(ctx, {out})",
                "EVP_MAC_CTX_free",
                "EVP_MAC_free",
            ],
            expected_behavior="success",
            oracle=["unexpected_failure_on_valid_sequence", "crash_or_sanitizer"],
            enabled=True,
            mutation_hints=["re-init and reuse", "second MAC output length observation"],
            render_cleanup=cleanup,
        ),
        seed_record(
            seed_id="mac_lifecycle_use_after_free_negative_control",
            seed_type="unsafe_negative_control",
            api_sequence=[
                'EVP_MAC_fetch(NULL, "HMAC", NULL)',
                "EVP_MAC_CTX_new(mac)",
                "EVP_MAC_CTX_free(ctx)",
                f"EVP_MAC_update(ctx, {message})",
                "EVP_MAC_free(mac)",
            ],
            expected_behavior="skip_or_disabled_by_default",
            oracle=["disabled_unsafe_control"],
            enabled=False,
            mutation_hints=["unsafe use-after-free negative control retained only as disabled metadata"],
            disabled_reason=(
                "Use-after-free is intentionally invalid memory use and must not be run by default "
                "as a normal campaign case."
            ),
            render_cleanup=cleanup,
        ),
    ]


def lifecycle_seeds_for_family(family: str) -> list[dict[str, Any]]:
    if family == "mac_lifecycle":
        return mac_lifecycle_seeds()
    if family == "evp_cipher_ctx_lifecycle":
        return evp_cipher_ctx_lifecycle_seeds()
    return evp_digest_ctx_lifecycle_seeds()


def build_manifest(
    *,
    family: str,
    profile: dict[str, Any],
    lookup: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, Any]:
    seeds = lifecycle_seeds_for_family(family)
    return {
        "schema": "lifecycle_seed_manifest_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": profile.get("track", "lifecycle"),
        "archetype": profile.get("archetype", "evp_context_lifecycle"),
        "target_library": profile.get("target_library", "openssl"),
        "seed_ready": True,
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "api_cards_used": lookup.get("api_cards_used", []),
        "previous_completed_family": {
            "family": previous.get("family", "pkey_verify_semantic"),
            "status": previous.get("status", "completed_no_candidate"),
        },
        "seeds": seeds,
        "next_stage": "generic_lifecycle_mutation_engine",
    }


def seed_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    return {
        "schema": "lifecycle_seed_summary_v1",
        "generated_at": now_iso(),
        "family": manifest.get("family"),
        "track": manifest.get("track"),
        "archetype": manifest.get("archetype"),
        "target_library": manifest.get("target_library"),
        "seed_count": len(seeds),
        "enabled_seed_count": len([item for item in seeds if item.get("enabled") is True]),
        "disabled_seed_count": len([item for item in seeds if item.get("enabled") is False]),
        "seed_ids": [item.get("seed_id") for item in seeds],
    }


def seed_readiness(manifest: dict[str, Any]) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    enabled = [item for item in seeds if item.get("enabled") is True]
    return {
        "schema": "lifecycle_seed_readiness_v1",
        "generated_at": now_iso(),
        "family": manifest.get("family"),
        "seed_ready": bool(manifest.get("seed_ready")) and len(enabled) >= 4,
        "ready_for_lifecycle_mutation": len(enabled) >= 4,
        "ready_for_render_plan": len(enabled) >= 4,
        "blocked_by": [],
        "next_stage": manifest.get("next_stage"),
    }


def quality_checks(
    *,
    profile: dict[str, Any],
    previous: dict[str, Any],
    lookup: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    seeds = manifest.get("seeds", []) or []
    family = str(manifest.get("family") or "evp_digest_ctx_lifecycle")
    prefix = family
    seed_ids = {item.get("seed_id") for item in seeds}
    enabled_seed_count = len([item for item in seeds if item.get("enabled") is True])
    unsafe = next(
        (
            item
            for item in seeds
            if item.get("seed_id") == f"{prefix}_use_after_free_negative_control"
        ),
        {},
    )
    lifecycle_oracles_defined = all(bool(item.get("oracle")) for item in seeds)
    base = {
        "schema": f"{family}_seed_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "previous_family_completed_no_candidate": bool(previous.get("completed_no_candidate")),
        "previous_family_skipped": bool(previous.get("skip_on_next_selection")),
        "family": manifest.get("family"),
        "track": manifest.get("track"),
        "archetype": manifest.get("archetype"),
        "target_library": manifest.get("target_library"),
        "rag_lookup_executed": True,
        "api_cards_used": bool(lookup.get("api_cards_used")),
        "family_profile_present": bool(profile),
        "seed_manifest_generated": bool(manifest),
        "seed_ready": bool(manifest.get("seed_ready")),
        "seed_count": len(seeds),
        "enabled_seed_count": enabled_seed_count,
        "valid_init_update_final_control_present": (
            f"{prefix}_valid_init_update_final_control" in seed_ids
            or f"{prefix}_valid_encrypt_init_update_final_control" in seed_ids
            or f"{prefix}_valid_hmac_init_update_final_control" in seed_ids
        ),
        "update_before_init_control_present": (
            f"{prefix}_update_before_init_control" in seed_ids
        ),
        "final_without_update_control_present": (
            f"{prefix}_final_without_update_control" in seed_ids
            or f"{prefix}_final_without_update_after_init_control" in seed_ids
        ),
        "update_after_final_control_present": (
            f"{prefix}_update_after_final_control" in seed_ids
            or f"{prefix}_update_after_final_observation_control" in seed_ids
        ),
        "reset_reuse_control_present": (
            f"{prefix}_reset_reuse_control" in seed_ids
            or f"{prefix}_reinit_reuse_control" in seed_ids
        ),
        "unsafe_use_after_free_disabled": unsafe.get("enabled") is False,
        "uses_der_parsing": bool(manifest.get("uses_der_parsing")),
        "uses_trailing_garbage": bool(manifest.get("uses_trailing_garbage")),
        "uses_full_consumption_oracle": bool(manifest.get("uses_full_consumption_oracle")),
        "lifecycle_oracles_defined": lifecycle_oracles_defined,
        "generic_lifecycle_seed_discovery_used": True,
        "family_specific_script_created": False,
        "render_executed": False,
        "compile_executed": False,
        "run_executed": False,
        "mapping_gate_bypassed": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "adapter_recipes_modified": False,
        "normalized_templates_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
    }
    pass_keys = [
        "previous_family_completed_no_candidate",
        "previous_family_skipped",
        "family_profile_present",
        "seed_manifest_generated",
        "seed_ready",
        "valid_init_update_final_control_present",
        "update_before_init_control_present",
        "final_without_update_control_present",
        "update_after_final_control_present",
        "reset_reuse_control_present",
        "unsafe_use_after_free_disabled",
        "lifecycle_oracles_defined",
        "generic_lifecycle_seed_discovery_used",
    ]
    fail_false_keys = [
        "uses_der_parsing",
        "uses_trailing_garbage",
        "uses_full_consumption_oracle",
        "family_specific_script_created",
        "render_executed",
        "compile_executed",
        "run_executed",
        "mapping_gate_bypassed",
        "api_key_logged",
        "main_feedback_written",
        "pattern_bank_modified",
        "adapter_recipes_modified",
        "normalized_templates_modified",
        "git_add_commit_push",
        "confirmed_vulnerability_claim",
    ]
    passed = (
        manifest.get("family") == family
        and manifest.get("track") == "lifecycle"
        and manifest.get("archetype") == profile.get("archetype", "evp_context_lifecycle")
        and manifest.get("target_library") == "openssl"
        and len(seeds) >= 5
        and enabled_seed_count >= 4
        and all(base.get(key) is True for key in pass_keys)
        and all(base.get(key) is False for key in fail_false_keys)
    )
    base["quality_status"] = "pass" if passed else "blocked"
    return base


def write_report(path: Path, manifest: dict[str, Any], qc: dict[str, Any]) -> None:
    report = f"""# {TASK} Report

## Selection

- previous family: pkey_verify_semantic
- previous status: completed_no_candidate
- selected family: {manifest.get('family')}
- selected track: {manifest.get('track')}
- archetype: {manifest.get('archetype')}

## Seed Discovery

- seed_ready: {manifest.get('seed_ready')}
- seed_count: {qc.get('seed_count')}
- enabled_seed_count: {qc.get('enabled_seed_count')}
- quality_status: {qc.get('quality_status')}

## Policy

No render, compile, run, feedback main-store write, pattern-bank update, adapter
recipe edit, normalized-template edit, git operation, or vulnerability claim was
performed. The disabled use-after-free seed is metadata only and must not be run
by default.
"""
    write_text(path, report)


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    family = str(args.family)

    profiles = load_family_profiles(repo_root / args.family_profiles)
    profile = family_profile(profiles, family)
    previous = previous_family_snapshot(repo_root / args.previous_family_root)
    policy = load_yaml(repo_root / args.novelty_policy)
    novelty = build_novelty_snapshot(policy, family, profile.get("track", "lifecycle"))
    lookup = lifecycle_api_card_lookup(repo_root, family)
    manifest = build_manifest(family=family, profile=profile, lookup=lookup, previous=previous)
    summary = seed_summary(manifest)
    readiness = seed_readiness(manifest)
    qc = quality_checks(profile=profile, previous=previous, lookup=lookup, manifest=manifest)

    dump_yaml(out_dir / "inputs/previous_family_snapshot.yaml", previous)
    dump_yaml(out_dir / "inputs/novelty_gate_snapshot.yaml", novelty)
    dump_yaml(out_dir / "rag/api_card_lookup.yaml", lookup)
    dump_yaml(out_dir / "seed_discovery/seed_manifest.yaml", manifest)
    dump_yaml(out_dir / "seed_discovery/seed_summary.yaml", summary)
    dump_yaml(out_dir / "seed_discovery/seed_readiness.yaml", readiness)
    dump_yaml(out_dir / f"validation/{family}_seed_quality_checks.yaml", qc)
    if family == "evp_digest_ctx_lifecycle":
        dump_yaml(out_dir / "validation/evp_digest_ctx_lifecycle_seed_quality_checks.yaml", qc)
    write_report(out_dir / f"reports/{family}_seed_discovery_report.md", manifest, qc)
    if family == "evp_digest_ctx_lifecycle":
        write_report(out_dir / "reports/evp_digest_ctx_lifecycle_seed_discovery_v1_report.md", manifest, qc)

    print(f"wrote {out_dir}")
    print(f"quality_status: {qc.get('quality_status')}")
    print(f"seed_count: {qc.get('seed_count')}")
    return 0 if qc.get("quality_status") == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
