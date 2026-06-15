"""Controlled campaign auto-bootstrap loop.

The loop reads family inventory plus manual audit feedback, registers only the
selected ready families, generates local minimal harnesses, compiles/runs them
against the local OpenSSL ASAN build, and stops on candidate evidence.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from analysis.analysis_records import dump_yaml, load_yaml, now_iso, write_text
from analysis.manual_codex_audit import (
    SELECTED_FAMILIES,
    case_records,
    compile_and_run,
    parse_oracle_events,
)


TASK = "campaign_auto_bootstrap_loop_v1"
DEFAULT_OUT_DIR = f"artifacts/campaigns/{TASK}"
DEFAULT_OPENSSL_INSTALL = "/home/wen/work/install-openssl-3.5.5-asan"
DEFAULT_MANUAL_AUDIT = "artifacts/manual_codex_audit/crypto_library_bug_hunt_v1"
DEFAULT_INVENTORY = "artifacts/reports/family_inventory_registry_reconcile_v2"
DEFAULT_PROFILES = "config/family_profiles.yaml"

PRIORITY = [
    "provider_fetch_lifecycle",
    "evp_pkey_context_lifecycle",
    "bn_usub_semantic",
    "ossl_store_lifecycle",
    "ossl_store_decoder_boundary",
    "cipher_aead_lifecycle",
    "cipher_aead_lifecycle_ccm",
    "cipher_aead_lifecycle_ctx_copy",
    "ec_arithmetic_semantic",
    "bignum_serialization_boundary",
]
PRIORITY_V2 = [
    "ossl_store_lifecycle",
    "ossl_store_decoder_boundary",
    "cipher_aead_lifecycle",
    "cipher_aead_lifecycle_ccm",
    "cipher_aead_lifecycle_ctx_copy",
    "ec_arithmetic_semantic",
    "bignum_serialization_boundary",
]
PRIORITY_V3 = [
    "cipher_aead_lifecycle_ccm",
    "cipher_aead_lifecycle_ctx_copy",
    "ec_arithmetic_semantic",
    "bignum_serialization_boundary",
    "cipher_aead_lifecycle",
    "ossl_store_lifecycle",
    "provider_fetch_lifecycle",
]
PRIORITY_CCM_FIX_RESUME = [
    "cipher_aead_lifecycle_ctx_copy",
    "ec_arithmetic_semantic",
    "bignum_serialization_boundary",
]
COMPLETED_NO_CANDIDATE = [
    "pkey_verify_semantic",
    "evp_digest_ctx_lifecycle",
    "evp_cipher_ctx_lifecycle",
    "mac_lifecycle",
]
COMPLETED_NO_CANDIDATE_V2 = COMPLETED_NO_CANDIDATE + [
    "provider_fetch_lifecycle",
    "evp_pkey_context_lifecycle",
    "bn_usub_semantic",
]
COMPLETED_NO_CANDIDATE_V3 = COMPLETED_NO_CANDIDATE_V2 + [
    "ossl_store_lifecycle",
    "ossl_store_decoder_boundary",
    "cipher_aead_lifecycle",
]
COMPLETED_NO_CANDIDATE_CCM_FIX_RESUME = COMPLETED_NO_CANDIDATE_V3 + [
    "cipher_aead_lifecycle_ccm",
]
KNOWN_PATTERN_ONLY = ["pkey_parsing"]
HISTORICAL_TESTED = ["secure_heap_state_lifecycle"]
PARSING_DEPRIORITIZED = [
    "x509_parsing",
    "pkey_parsing",
    "pkcs8_parsing",
    "x509_crl_parsing",
    "cms_container_parsing",
    "pkcs_container_parsing",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    parser.add_argument("--openssl-install", default=DEFAULT_OPENSSL_INSTALL)
    parser.add_argument("--manual-audit-root", default=DEFAULT_MANUAL_AUDIT)
    parser.add_argument("--inventory-root", default=DEFAULT_INVENTORY)
    parser.add_argument("--family-profiles", default=DEFAULT_PROFILES)
    parser.add_argument("--max-families", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=int, default=10)
    parser.add_argument("--campaign-version", choices=["v1", "v2", "v3", "ccm_fix_resume"], default="v1")
    parser.add_argument(
        "--ccm-triage-root",
        default="artifacts/triage/ccm_plaintext_length_not_announced_triage_v1",
    )
    return parser.parse_args()


def profile_for(family: str, manual_profiles: dict[str, Any], inventory_profiles: dict[str, Any]) -> dict[str, Any]:
    manual = ((manual_profiles.get("profiles") or {}).get(family) or {}).copy()
    inventory = ((inventory_profiles.get("families") or {}).get(family) or {}).copy()
    source = manual or inventory
    if not source:
        source = {
            "track": "lifecycle" if "lifecycle" in family else "semantic",
            "archetype": family,
            "target_library": "openssl",
        }
    if family == "ossl_store_lifecycle" and not manual:
        source = {
            "track": "lifecycle",
            "archetype": "ossl_store_context_lifecycle",
            "target_library": "openssl",
        }
    elif family == "cipher_aead_lifecycle_ccm" and not manual:
        source = {
            "track": "lifecycle",
            "archetype": "cipher_aead_ccm_state_order_lifecycle",
            "target_library": "openssl",
        }
    elif family == "cipher_aead_lifecycle_ctx_copy" and not manual:
        source = {
            "track": "lifecycle",
            "archetype": "cipher_ctx_copy_lifecycle",
            "target_library": "openssl",
        }
    elif family == "ec_arithmetic_semantic" and not manual:
        source = {
            "track": "semantic",
            "archetype": "ec_group_point_arithmetic_semantic",
            "target_library": "openssl",
        }
    elif family == "bignum_serialization_boundary" and not manual:
        source = {
            "track": "boundary",
            "archetype": "bignum_serialization_length_boundary",
            "target_library": "openssl",
        }
    track = str(source.get("track") or ("lifecycle" if "lifecycle" in family else "semantic"))
    archetype = str(source.get("archetype") or family)
    render_mode = "lifecycle_harness" if track == "lifecycle" else "semantic_harness"
    return {
        "family": family,
        "track": track,
        "archetype": archetype,
        "target_library": str(source.get("target_library") or "openssl"),
        "status": "profile_ready",
        "seed_discovery": {"enabled": True, "mode": "manual_audit_bootstrap"},
        "mutation": {"engine": "manual_audit_minimal_mutation_rules"},
        "render": {"mode": render_mode},
        "oracle": [
            "unexpected_failure_on_valid_sequence",
            "unexpected_success_after_invalid_state",
            "state_transition_observation",
            "semantic_divergence_candidate",
            "crash_or_sanitizer",
        ],
        "avoid_patterns": [
            "der_single_object_trailing_garbage_full_consumption",
            "secure_heap_state_lifecycle_issue_28669",
        ],
        "notes": "Auto-registered by campaign_auto_bootstrap_loop_v1 from manual audit feedback.",
    }


def register_profile(repo_root: Path, profiles_path: Path, family: str, profile: dict[str, Any]) -> bool:
    data = load_yaml(profiles_path)
    families = data.setdefault("families", {})
    if family in families:
        return False
    families[family] = profile
    dump_yaml(profiles_path, data)
    return True


def family_card(family: str, profile: dict[str, Any]) -> dict[str, Any]:
    apis = {
        "provider_fetch_lifecycle": [
            "OSSL_PROVIDER_load",
            "EVP_MD_fetch",
            "EVP_CIPHER_fetch",
            "EVP_MAC_fetch",
            "EVP_MD_free",
            "EVP_CIPHER_free",
            "EVP_MAC_free",
            "OSSL_PROVIDER_unload",
        ],
        "evp_pkey_context_lifecycle": [
            "EVP_PKEY_CTX_new_id",
            "EVP_PKEY_keygen_init",
            "EVP_PKEY_keygen",
            "EVP_PKEY_CTX_free",
            "EVP_PKEY_free",
        ],
        "bn_usub_semantic": [
            "BN_usub",
            "BN_sub",
            "BN_add",
            "BN_cmp",
            "BN_bn2bin",
            "BN_bin2bn",
        ],
        "ossl_store_lifecycle": [
            "OSSL_STORE_open",
            "OSSL_STORE_load",
            "OSSL_STORE_eof",
            "OSSL_STORE_error",
            "OSSL_STORE_close",
        ],
        "cipher_aead_lifecycle_ccm": [
            "EVP_CIPHER_CTX_new",
            "EVP_EncryptInit_ex",
            "EVP_EncryptUpdate",
            "EVP_EncryptFinal_ex",
            "EVP_DecryptInit_ex",
            "EVP_DecryptUpdate",
            "EVP_DecryptFinal_ex",
            "EVP_CIPHER_CTX_ctrl",
            "EVP_aes_128_ccm",
            "EVP_CIPHER_CTX_free",
        ],
        "cipher_aead_lifecycle_ctx_copy": [
            "EVP_CIPHER_CTX_copy",
            "EVP_CIPHER_CTX_new",
            "EVP_CIPHER_CTX_reset",
            "EVP_CIPHER_CTX_free",
            "EVP_aes_128_gcm",
            "EVP_aes_128_ccm",
        ],
        "ec_arithmetic_semantic": [
            "EC_GROUP_new_by_curve_name",
            "EC_POINT_new",
            "EC_POINT_mul",
            "EC_POINT_add",
            "EC_POINT_invert",
            "EC_POINT_is_at_infinity",
            "EC_POINT_cmp",
            "BN_CTX_new",
            "BN_new",
        ],
        "bignum_serialization_boundary": [
            "BN_bin2bn",
            "BN_bn2bin",
            "BN_bn2binpad",
            "BN_hex2bn",
            "BN_bn2hex",
            "BN_dec2bn",
            "BN_bn2dec",
            "BN_num_bytes",
            "BN_is_negative",
            "BN_set_negative",
            "BN_cmp",
        ],
    }
    return {
        "schema": "family_card_v1",
        "family": family,
        "track": profile["track"],
        "archetype": profile["archetype"],
        "target_library": "openssl",
        "main_apis": apis.get(family, []),
        "valid_sequence": "local minimal control sequence generated from manual audit feedback",
        "invalid_or_observation_sequences": [
            "operation before required init",
            "invalid algorithm/property or contract boundary",
            "documented observation path",
        ],
        "oracle_labels": profile["oracle"],
        "avoid_patterns": profile["avoid_patterns"],
        "claim_policy": {"confirmed_vulnerability": False, "cve": False, "exploitable": False},
    }


def ensure_family_card(repo_root: Path, family: str, profile: dict[str, Any]) -> bool:
    path = repo_root / "knowledge/family_cards" / f"{family}.yaml"
    if path.exists():
        return False
    dump_yaml(path, family_card(family, profile))
    return True


def queue_docs(
    repo_root: Path,
    manual_root: Path,
    inventory_root: Path,
    out_dir: Path,
    max_families: int,
    *,
    priority: list[str] | None = None,
    completed_no_candidate: list[str] | None = None,
) -> list[str]:
    manual_profiles = load_yaml(manual_root / "feedback_to_pipeline/proposed_family_profiles.yaml")
    inventory_profiles = load_yaml(inventory_root / "proposed_family_profiles.yaml")
    matrix = load_yaml(inventory_root / "family_status_matrix.yaml")
    matrix_by_family = {str(item.get("family")): item for item in matrix.get("families", []) or []}
    priority = priority or PRIORITY
    completed_no_candidate = completed_no_candidate or COMPLETED_NO_CANDIDATE
    queue = []
    for index, family in enumerate(priority, start=1):
        row = matrix_by_family.get(family, {})
        queue.append(
            {
                "rank": index,
                "family": family,
                "track": row.get("track") or ("lifecycle" if "lifecycle" in family else "semantic"),
                "manual_feedback_available": family in (manual_profiles.get("profiles") or {}),
                "inventory_profile_available": family in (inventory_profiles.get("families") or {}),
                "remaining_novel": row.get("remaining_novel", True),
            }
        )
    filtered = [
        item
        for item in queue
        if item["family"] not in completed_no_candidate
        and item["family"] not in KNOWN_PATTERN_ONLY
        and item["family"] not in HISTORICAL_TESTED
        and item["family"] not in PARSING_DEPRIORITIZED
    ]
    dump_yaml(out_dir / "family_queue.yaml", {"schema": "campaign_family_queue_v1", "families": queue})
    dump_yaml(
        out_dir / "family_queue_after_filter.yaml",
        {"schema": "campaign_family_queue_after_filter_v1", "max_families": max_families, "families": filtered},
    )
    return [item["family"] for item in filtered[:max_families]]


def family_cases(family: str) -> list[dict[str, Any]]:
    if family == "ossl_store_lifecycle":
        return ossl_store_cases()
    if family == "ossl_store_decoder_boundary":
        return ossl_store_decoder_cases()
    if family == "cipher_aead_lifecycle":
        return cipher_aead_cases()
    if family == "cipher_aead_lifecycle_ccm":
        return ccm_cases()
    if family == "cipher_aead_lifecycle_ctx_copy":
        return ctx_copy_cases()
    if family == "ec_arithmetic_semantic":
        return ec_arithmetic_cases()
    if family == "bignum_serialization_boundary":
        return bignum_serialization_cases()
    return [item for item in case_records() if item["family"] == family]


def v3_case_record(
    family: str,
    track: str,
    case_id: str,
    expected: str,
    strategy: str,
    source: str,
    *,
    enabled: bool = True,
    deferred_reason: str = "",
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "family": family,
        "track": track,
        "expected_behavior": expected,
        "mutation_strategy": strategy,
        "enabled": enabled,
        "deferred_reason": deferred_reason,
        "source": source,
    }


def c_event_print(family: str) -> str:
    return f"""
    printf("ORACLE_EVENT family={family}\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);
"""


def ccm_cases() -> list[dict[str, Any]]:
    raw = [
        ("ccm_valid_encrypt_decrypt_control", "success", "valid_encrypt_decrypt"),
        ("ccm_decrypt_without_tag", "error_or_documented", "decrypt_without_tag"),
        ("ccm_set_tag_after_decrypt_update", "error_or_documented", "set_tag_after_decrypt_update"),
        ("ccm_set_ivlen_after_key_iv_init", "observation", "set_ivlen_after_key_iv_init"),
        ("ccm_payload_only_plaintext_length_not_announced", "observation", "plaintext_length_not_announced"),
        ("ccm_with_aad_plaintext_length_not_announced", "error_or_documented", "with_aad_plaintext_length_not_announced"),
        ("ccm_aad_order_mutation", "observation", "aad_order_mutation"),
        ("ccm_zero_length_plaintext", "observation", "zero_length_plaintext"),
        ("ccm_wrong_tag", "error_or_documented", "wrong_tag"),
        ("ccm_truncated_tag_length", "observation", "truncated_tag_length"),
        ("ccm_reset_reuse", "success", "reset_reuse"),
    ]
    return [
        v3_case_record(
            "cipher_aead_lifecycle_ccm",
            "lifecycle",
            case_id,
            expected,
            strategy,
            ccm_case_source(case_id, expected, strategy),
        )
        for case_id, expected, strategy in raw
    ]


def ccm_case_source(case_id: str, expected: str, strategy: str) -> str:
    encrypt_common = """
static int ccm_encrypt_once(const unsigned char *pt, int pt_len,
                            unsigned char *ct, unsigned char *tag, int tag_len)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL) return 0;
    ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL) == 1;
    ok = ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, NULL, &len, NULL, pt_len) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) == 1;
    if (pt_len > 0)
        ok = ok && EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) == 1;
    ok = ok && EVP_EncryptFinal_ex(ctx, ct + len, &len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int ccm_decrypt_once(const unsigned char *ct, int ct_len,
                            const unsigned char *tag, int tag_len, int set_tag)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char out[64] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int ok = 0;
    if (ctx == NULL) return 0;
    ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL) == 1;
    if (set_tag)
        ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, (void *)tag) == 1;
    ok = ok && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, NULL, &len, NULL, ct_len) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof(aad)) == 1;
    if (ct_len > 0)
        ok = ok && EVP_DecryptUpdate(ctx, out, &len, ct, ct_len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}
"""
    if strategy == "valid_encrypt_decrypt":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 16);
    dec_ok = ccm_decrypt_once(ciphertext, plaintext_len, tag, 16, 1);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";
"""
    elif strategy == "decrypt_without_tag":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 16);
    dec_ok = ccm_decrypt_once(ciphertext, plaintext_len, tag, 16, 0);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
"""
    elif strategy == "set_tag_after_decrypt_update":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 16);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL && enc_ok) {
        ret1 = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret2 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        ret3 = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
        ret4 = EVP_DecryptUpdate(ctx, NULL, &out_len, NULL, plaintext_len);
        ret5 = EVP_DecryptUpdate(ctx, out, &out_len, ciphertext, plaintext_len);
        ret6 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag);
        actual_behavior = (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1 && ret5 == 1 && ret6 == 1) ? "success" : "error";
    }
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
"""
    elif strategy == "set_ivlen_after_key_iv_init":
        body = """
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL) {
        ret1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, key, iv);
        ret2 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        actual_behavior = (ret1 == 1 && ret2 == 1) ? "success" : "error";
    }
"""
    elif strategy == "plaintext_length_not_announced":
        body = """
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL) {
        ret1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret2 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        ret3 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);
        ret4 = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        ret5 = EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len);
        actual_behavior = (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1 && ret5 == 1) ? "success" : "error";
    }
"""
    elif strategy == "with_aad_plaintext_length_not_announced":
        body = """
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL) {
        ret1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret2 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        ret3 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);
        ret4 = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        ret5 = EVP_EncryptUpdate(ctx, NULL, &out_len, aad, sizeof(aad));
        ret6 = EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len);
        ret7 = EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
        actual_behavior = (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1 && ret5 == 1 && ret6 == 1 && ret7 == 1) ? "success" : "error";
    }
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
"""
    elif strategy == "aad_order_mutation":
        body = """
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL) {
        ret1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret2 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        ret3 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);
        ret4 = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        ret5 = EVP_EncryptUpdate(ctx, NULL, &out_len, NULL, plaintext_len);
        ret6 = EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len);
        ret7 = EVP_EncryptUpdate(ctx, NULL, &out_len, aad, sizeof(aad));
        actual_behavior = (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1 && ret5 == 1 && ret6 == 1 && ret7 == 1) ? "success" : "error";
    }
"""
    elif strategy == "zero_length_plaintext":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, 0, ciphertext, tag, 16);
    dec_ok = ccm_decrypt_once(ciphertext, 0, tag, 16, 1);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";
"""
    elif strategy == "wrong_tag":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 16);
    tag[0] ^= 0x5a;
    dec_ok = ccm_decrypt_once(ciphertext, plaintext_len, tag, 16, 1);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
"""
    elif strategy == "truncated_tag_length":
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 8);
    dec_ok = ccm_decrypt_once(ciphertext, plaintext_len, tag, 8, 1);
    actual_behavior = (enc_ok && dec_ok) ? "success" : "error";
"""
    else:
        body = """
    enc_ok = ccm_encrypt_once(plaintext, plaintext_len, ciphertext, tag, 16);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL && enc_ok) {
        ret1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret2 = EVP_CIPHER_CTX_reset(ctx);
        ret3 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
        ret4 = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
        actual_behavior = (ret1 == 1 && ret2 == 1 && ret3 == 1 && ret4 == 1) ? "success" : "error";
    }
"""
    return f"""/*
 * Auto campaign EVP CCM lifecycle harness.
 * Local state-order mutation only; no exploit chain or DER consumption oracle.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
{encrypt_common}
int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int enc_ok = 0, dec_ok = 0;
    int ret1 = 0, ret2 = 0, ret3 = 0, ret4 = 0, ret5 = 0, ret6 = 0, ret7 = 0;
    int out_len = 0;
    unsigned char key[16] = {{0}};
    unsigned char iv[12] = {{0}};
    unsigned char aad[8] = {{1,2,3,4,5,6,7,8}};
    unsigned char plaintext[] = "local ccm msg";
    unsigned char ciphertext[64] = {{0}};
    unsigned char out[64] = {{0}};
    unsigned char tag[16] = {{0}};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    EVP_CIPHER_CTX *ctx = NULL;

{body}
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
{c_event_print("cipher_aead_lifecycle_ccm")}
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}}
"""


def ctx_copy_cases() -> list[dict[str, Any]]:
    raw = [
        ("ctx_copy_gcm_before_update", "success", "copy_initialized_gcm_before_update", True, ""),
        ("ctx_copy_gcm_after_aad", "success", "copy_gcm_after_aad", True, ""),
        ("ctx_copy_gcm_after_plaintext_before_final", "success", "copy_gcm_after_plaintext_before_final", True, ""),
        ("ctx_copy_finalized_observation", "observation", "copy_finalized_ctx", True, ""),
        ("ctx_copy_reset_observation", "observation", "copy_reset_ctx", True, ""),
        ("ctx_copy_uninitialized_observation", "observation", "copy_uninitialized_ctx", True, ""),
        ("ctx_copy_source_into_initialized_destination", "success", "copy_source_into_initialized_destination", True, ""),
        ("ctx_copy_into_reset_destination", "success", "copy_into_reset_destination", True, ""),
        ("ctx_copy_self_copy_disabled", "disabled_unsafe_control", "self_copy", False, "self-copy is disabled by default"),
        ("ctx_copy_use_after_free_source_disabled", "disabled_unsafe_control", "use_after_free_source", False, "use-after-free source is disabled by default"),
    ]
    return [
        v3_case_record(
            "cipher_aead_lifecycle_ctx_copy",
            "lifecycle",
            case_id,
            expected,
            strategy,
            ctx_copy_case_source(case_id, expected, strategy),
            enabled=enabled,
            deferred_reason=reason,
        )
        for case_id, expected, strategy, enabled, reason in raw
    ]


def ctx_copy_case_source(case_id: str, expected: str, strategy: str) -> str:
    setup_body = """
static int init_gcm(EVP_CIPHER_CTX *ctx)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    return EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) == 1;
}
"""
    if strategy == "copy_initialized_gcm_before_update":
        body = "ret1 = init_gcm(src); ret2 = EVP_CIPHER_CTX_copy(dst, src); actual_behavior = (ret1 && ret2 == 1) ? \"success\" : \"error\";"
    elif strategy == "copy_gcm_after_aad":
        body = """
    ret1 = init_gcm(src);
    ret3 = EVP_EncryptUpdate(src, NULL, &out_len, aad, sizeof(aad));
    ret2 = EVP_CIPHER_CTX_copy(dst, src);
    actual_behavior = (ret1 && ret3 == 1 && ret2 == 1) ? "success" : "error";
"""
    elif strategy == "copy_gcm_after_plaintext_before_final":
        body = """
    ret1 = init_gcm(src);
    ret3 = EVP_EncryptUpdate(src, out, &out_len, plaintext, plaintext_len);
    ret2 = EVP_CIPHER_CTX_copy(dst, src);
    actual_behavior = (ret1 && ret3 == 1 && ret2 == 1) ? "success" : "error";
"""
    elif strategy == "copy_finalized_ctx":
        body = """
    ret1 = init_gcm(src);
    ret3 = EVP_EncryptUpdate(src, out, &out_len, plaintext, plaintext_len);
    ret4 = EVP_EncryptFinal_ex(src, out + out_len, &final_len);
    ret2 = EVP_CIPHER_CTX_copy(dst, src);
    actual_behavior = (ret1 && ret3 == 1 && ret4 == 1 && ret2 == 1) ? "success" : "error";
"""
    elif strategy == "copy_reset_ctx":
        body = "ret1 = EVP_CIPHER_CTX_reset(src); ret2 = EVP_CIPHER_CTX_copy(dst, src); actual_behavior = (ret1 == 1 && ret2 == 1) ? \"success\" : \"error\";"
    elif strategy == "copy_uninitialized_ctx":
        body = "ret2 = EVP_CIPHER_CTX_copy(dst, src); actual_behavior = (ret2 == 1) ? \"success\" : \"error\";"
    elif strategy == "copy_source_into_initialized_destination":
        body = "ret1 = init_gcm(src); ret4 = init_gcm(dst); ret2 = EVP_CIPHER_CTX_copy(dst, src); actual_behavior = (ret1 && ret4 && ret2 == 1) ? \"success\" : \"error\";"
    else:
        body = "ret1 = init_gcm(src); ret4 = EVP_CIPHER_CTX_reset(dst); ret2 = EVP_CIPHER_CTX_copy(dst, src); actual_behavior = (ret1 && ret4 == 1 && ret2 == 1) ? \"success\" : \"error\";"
    return f"""/*
 * Auto campaign EVP_CIPHER_CTX_copy lifecycle harness.
 * Unsafe self-copy and use-after-free cases are recorded as disabled seeds only.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
{setup_body}
int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret1 = 0, ret2 = 0, ret3 = 0, ret4 = 0;
    unsigned char aad[8] = {{1,2,3,4,5,6,7,8}};
    unsigned char plaintext[] = "local gcm copy msg";
    unsigned char out[128] = {{0}};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *src = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dst = EVP_CIPHER_CTX_new();

    if (src == NULL || dst == NULL)
        goto done;
    {body}
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
{c_event_print("cipher_aead_lifecycle_ctx_copy")}
    EVP_CIPHER_CTX_free(src);
    EVP_CIPHER_CTX_free(dst);
    return 0;
}}
"""


def ec_arithmetic_cases() -> list[dict[str, Any]]:
    raw = [
        ("ec_generator_mul_one_control", "semantic_equivalence", "generator_multiply_by_one"),
        ("ec_generator_mul_zero_infinity", "observation", "generator_multiply_by_zero"),
        ("ec_point_add_infinity_identity", "semantic_equivalence", "point_add_infinity"),
        ("ec_point_add_inverse_infinity", "semantic_equivalence", "point_add_inverse"),
        ("ec_scalar_order_boundary", "observation", "scalar_order_boundary"),
        ("ec_scalar_order_plus_one_equivalence", "semantic_equivalence", "scalar_order_plus_one"),
        ("ec_invalid_affine_coordinates_observation", "observation", "invalid_affine_coordinates"),
        ("ec_mul_null_bn_ctx_observation", "observation", "null_bn_ctx"),
        ("ec_invert_twice_compare", "semantic_equivalence", "invert_twice_compare"),
        ("ec_group_mismatch_operation_observation", "observation", "group_mismatch_operation"),
    ]
    return [
        v3_case_record(
            "ec_arithmetic_semantic",
            "semantic",
            case_id,
            expected,
            strategy,
            ec_arithmetic_case_source(case_id, expected, strategy),
        )
        for case_id, expected, strategy in raw
    ]


def ec_arithmetic_case_source(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "generator_multiply_by_one":
        body = """
    BN_one(k);
    ret = EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_cmp(group, p, gen, bn_ctx) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "generator_multiply_by_zero":
        body = """
    BN_zero(k);
    ret = EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_is_at_infinity(group, p)) ? "success" : "error";
"""
    elif strategy == "point_add_infinity":
        body = """
    BN_one(k);
    EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    EC_POINT_set_to_infinity(group, q);
    ret = EC_POINT_add(group, r, p, q, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_cmp(group, r, p, bn_ctx) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "point_add_inverse":
        body = """
    BN_one(k);
    EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    EC_POINT_copy(q, p);
    EC_POINT_invert(group, q, bn_ctx);
    ret = EC_POINT_add(group, r, p, q, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_is_at_infinity(group, r)) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "scalar_order_boundary":
        body = """
    ret = EC_GROUP_get_order(group, order, bn_ctx);
    ret = ret && EC_POINT_mul(group, p, order, NULL, NULL, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_is_at_infinity(group, p)) ? "success" : "error";
"""
    elif strategy == "scalar_order_plus_one":
        body = """
    ret = EC_GROUP_get_order(group, order, bn_ctx);
    BN_copy(k, order);
    BN_add_word(k, 1);
    ret = ret && EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    actual_behavior = (ret == 1 && EC_POINT_cmp(group, p, gen, bn_ctx) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "invalid_affine_coordinates":
        body = """
    BN_set_word(x, 1);
    BN_set_word(y, 1);
    ret = EC_POINT_set_affine_coordinates(group, p, x, y, bn_ctx);
    actual_behavior = (ret == 1) ? "success" : "error";
"""
    elif strategy == "null_bn_ctx":
        body = """
    BN_one(k);
    ret = EC_POINT_mul(group, p, k, NULL, NULL, NULL);
    actual_behavior = (ret == 1) ? "success" : "error";
"""
    elif strategy == "invert_twice_compare":
        body = """
    BN_one(k);
    EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    EC_POINT_copy(q, p);
    EC_POINT_invert(group, q, bn_ctx);
    EC_POINT_invert(group, q, bn_ctx);
    actual_behavior = (EC_POINT_cmp(group, p, q, bn_ctx) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    else:
        body = """
    group2 = EC_GROUP_new_by_curve_name(NID_secp384r1);
    BN_one(k);
    ret = EC_POINT_mul(group, p, k, NULL, NULL, bn_ctx);
    ret2 = (group2 != NULL) ? EC_POINT_add(group2, q, p, p, bn_ctx) : 0;
    actual_behavior = (ret == 1 && ret2 == 1) ? "success" : "error";
"""
    return f"""/*
 * Auto campaign EC arithmetic semantic harness.
 * Local mathematical identities only; invalid observations are not vulnerability claims.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret = 0, ret2 = 0;
    BN_CTX *bn_ctx = BN_CTX_new();
    BIGNUM *k = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP *group2 = NULL;
    EC_POINT *p = NULL;
    EC_POINT *q = NULL;
    EC_POINT *r = NULL;
    const EC_POINT *gen = NULL;

    if (bn_ctx == NULL || k == NULL || order == NULL || x == NULL || y == NULL || group == NULL)
        goto done;
    p = EC_POINT_new(group);
    q = EC_POINT_new(group);
    r = EC_POINT_new(group);
    gen = EC_GROUP_get0_generator(group);
    if (p == NULL || q == NULL || r == NULL || gen == NULL)
        goto done;
{body}

done:
{c_event_print("ec_arithmetic_semantic")}
    EC_POINT_free(p);
    EC_POINT_free(q);
    EC_POINT_free(r);
    EC_GROUP_free(group2);
    EC_GROUP_free(group);
    BN_free(k);
    BN_free(order);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);
    return 0;
}}
"""


def bignum_serialization_cases() -> list[dict[str, Any]]:
    raw = [
        ("bn_binary_roundtrip_positive_control", "semantic_equivalence", "binary_roundtrip_positive"),
        ("bn_zero_value_roundtrip", "semantic_equivalence", "zero_value_roundtrip"),
        ("bn_leading_zero_bytes_observation", "observation", "leading_zero_bytes"),
        ("bn_negative_hex_serialization_observation", "observation", "negative_hex_serialization"),
        ("bn_negative_dec_serialization_observation", "observation", "negative_dec_serialization"),
        ("bn_bn2binpad_exact_size", "success", "bn2binpad_exact_size"),
        ("bn_bn2binpad_too_small", "error_or_documented", "bn2binpad_too_small"),
        ("bn_empty_input_bin2bn_observation", "observation", "empty_input_bin2bn"),
        ("bn_large_bounded_input_roundtrip", "semantic_equivalence", "large_bounded_input"),
        ("bn_hex_invalid_string_reject", "error_or_documented", "hex_invalid_string"),
        ("bn_dec_invalid_string_reject", "error_or_documented", "dec_invalid_string"),
        ("bn_output_length_consistency_check", "semantic_equivalence", "output_length_consistency"),
        ("bn_negative_zero_normalization", "observation", "negative_zero_normalization"),
    ]
    return [
        v3_case_record(
            "bignum_serialization_boundary",
            "boundary",
            case_id,
            expected,
            strategy,
            bignum_serialization_case_source(case_id, expected, strategy),
        )
        for case_id, expected, strategy in raw
    ]


def bignum_serialization_case_source(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "binary_roundtrip_positive":
        body = """
    BN_hex2bn(&a, "010203A0");
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, len);
    b = BN_bin2bn(buf, ret, NULL);
    actual_behavior = (ret == len && b != NULL && BN_cmp(a, b) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "zero_value_roundtrip":
        body = """
    BN_zero(a);
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, 1);
    b = BN_bin2bn(buf, ret, NULL);
    actual_behavior = (ret == 1 && b != NULL && BN_is_zero(b)) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "leading_zero_bytes":
        body = """
    unsigned char in[] = {0x00, 0x00, 0x01, 0x02};
    a = BN_bin2bn(in, sizeof(in), NULL);
    len = BN_num_bytes(a);
    actual_behavior = (a != NULL && len == 2) ? "success" : "error";
"""
    elif strategy == "negative_hex_serialization":
        body = """
    BN_set_word(a, 7);
    BN_set_negative(a, 1);
    str = BN_bn2hex(a);
    actual_behavior = (str != NULL && str[0] == '-') ? "success" : "error";
"""
    elif strategy == "negative_dec_serialization":
        body = """
    BN_set_word(a, 7);
    BN_set_negative(a, 1);
    str = BN_bn2dec(a);
    actual_behavior = (str != NULL && str[0] == '-') ? "success" : "error";
"""
    elif strategy == "bn2binpad_exact_size":
        body = """
    BN_hex2bn(&a, "A1B2C3");
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, len);
    actual_behavior = (ret == len) ? "success" : "error";
"""
    elif strategy == "bn2binpad_too_small":
        body = """
    BN_hex2bn(&a, "A1B2C3");
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, len - 1);
    actual_behavior = (ret >= 0) ? "success" : "error";
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
"""
    elif strategy == "empty_input_bin2bn":
        body = """
    a = BN_bin2bn(buf, 0, NULL);
    actual_behavior = (a != NULL && BN_is_zero(a)) ? "success" : "error";
"""
    elif strategy == "large_bounded_input":
        body = """
    for (int i = 0; i < 64; i++) buf[i] = (unsigned char)(i + 1);
    a = BN_bin2bn(buf, 64, NULL);
    ret = BN_bn2binpad(a, out, 64);
    b = BN_bin2bn(out, ret, NULL);
    actual_behavior = (a != NULL && b != NULL && ret == 64 && BN_cmp(a, b) == 0) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    elif strategy == "hex_invalid_string":
        body = """
    ret = BN_hex2bn(&a, "12nothex34");
    actual_behavior = (ret == 0) ? "error" : "success";
"""
    elif strategy == "dec_invalid_string":
        body = """
    ret = BN_dec2bn(&a, "12notdec34");
    actual_behavior = (ret == 0) ? "error" : "success";
"""
    elif strategy == "output_length_consistency":
        body = """
    BN_hex2bn(&a, "0102030405");
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, len);
    actual_behavior = (ret == len && len == 5) ? "success" : "error";
    semantic_mismatch = strcmp(actual_behavior, "success") != 0;
"""
    else:
        body = """
    BN_zero(a);
    BN_set_negative(a, 1);
    actual_behavior = (!BN_is_negative(a) && BN_is_zero(a)) ? "success" : "error";
"""
    return f"""/*
 * Auto campaign BIGNUM serialization boundary harness.
 * Local serialization/length semantics only.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret = 0;
    int len = 0;
    unsigned char buf[128] = {{0}};
    unsigned char out[128] = {{0}};
    BIGNUM *a = BN_new();
    BIGNUM *b = NULL;
    char *str = NULL;

    if (a == NULL)
        goto done;
{body}
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
{c_event_print("bignum_serialization_boundary")}
    OPENSSL_free(str);
    BN_free(a);
    BN_free(b);
    return 0;
}}
"""


def ossl_store_cases() -> list[dict[str, Any]]:
    cases = [
        ("ossl_store_open_nonexistent_path", "error_or_documented", "open_nonexistent_path", True),
        ("ossl_store_open_empty_file", "error_or_documented", "open_empty_file", True),
        ("ossl_store_open_random_text_file", "error_or_documented", "open_random_text_file", True),
        ("ossl_store_load_after_eof_observation", "observation", "load_after_eof", True),
        ("ossl_store_valid_open_load_close_control_deferred", "success_or_documented", "valid_open_load_close_control", False),
        ("ossl_store_repeated_close_disabled", "disabled_unsafe_control", "repeated_close", False),
        ("ossl_store_load_after_close_disabled", "disabled_unsafe_control", "load_after_close", False),
    ]
    records = []
    for case_id, expected, strategy, enabled in cases:
        records.append(
            {
                "case_id": case_id,
                "family": "ossl_store_lifecycle",
                "track": "lifecycle",
                "expected_behavior": expected,
                "mutation_strategy": strategy,
                "enabled": enabled,
                "source": ossl_store_case_source(case_id, expected, strategy),
                "deferred_reason": "" if enabled else "unsafe or unavailable local valid object control is not executed by default",
            }
        )
    return records


def ossl_store_case_source(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "open_nonexistent_path":
        setup = 'const char *uri = "file:/tmp/crypto_pattern_fuzz_no_such_store_input.pem";'
        body = 'ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL); actual_behavior = (ctx == NULL) ? "error" : "success";'
    elif strategy == "open_empty_file":
        setup = 'const char *uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt";'
        body = 'ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL); actual_behavior = (ctx == NULL) ? "error" : "success";'
    elif strategy == "open_random_text_file":
        setup = 'const char *uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_random.txt";'
        body = 'ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL); actual_behavior = (ctx == NULL) ? "error" : "success";'
    elif strategy == "load_after_eof":
        setup = 'const char *uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt";'
        body = """
    ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (ctx != NULL) {
        while (!OSSL_STORE_eof(ctx) && !OSSL_STORE_error(ctx)) {
            info = OSSL_STORE_load(ctx);
            OSSL_STORE_INFO_free(info);
            info = NULL;
        }
        info = OSSL_STORE_load(ctx);
        actual_behavior = (info == NULL) ? "error" : "success";
    } else {
        actual_behavior = "error";
    }
"""
    else:
        setup = 'const char *uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt";'
        body = 'actual_behavior = "error";'
    return f"""/*
 * Auto campaign OSSL_STORE lifecycle harness.
 * Local files only; no DER trailing-garbage or full-consumption oracle.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/store.h>

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    {setup}

    {body}

    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family=ossl_store_lifecycle\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);

    OSSL_STORE_INFO_free(info);
    if (ctx != NULL)
        OSSL_STORE_close(ctx);
    return 0;
}}
"""


def ossl_store_decoder_cases() -> list[dict[str, Any]]:
    raw = [
        ("ossl_store_decoder_invalid_uri_scheme", "observation", "invalid_uri_scheme"),
        ("ossl_store_decoder_missing_loader", "observation", "missing_loader"),
        ("ossl_store_decoder_empty_decoder_input", "observation", "empty_decoder_input"),
    ]
    return [
        {
            "case_id": case_id,
            "family": "ossl_store_decoder_boundary",
            "track": "boundary",
            "expected_behavior": expected,
            "mutation_strategy": strategy,
            "enabled": True,
            "source": ossl_store_decoder_case_source(case_id, expected, strategy),
        }
        for case_id, expected, strategy in raw
    ]


def ossl_store_decoder_case_source(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "invalid_uri_scheme":
        uri = "nosuchscheme:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt"
    elif strategy == "missing_loader":
        uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_unknown.ext"
    else:
        uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt"
    return f"""/*
 * Auto campaign OSSL_STORE decoder boundary harness.
 * Local URI/format boundary only; no DER trailing-garbage or full-consumption oracle.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/store.h>

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    OSSL_STORE_CTX *ctx = OSSL_STORE_open("{uri}", NULL, NULL, NULL, NULL);

    if (ctx != NULL)
        actual_behavior = "success";

    printf("ORACLE_EVENT family=ossl_store_decoder_boundary\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);

    if (ctx != NULL)
        OSSL_STORE_close(ctx);
    return 0;
}}
"""


def cipher_aead_cases() -> list[dict[str, Any]]:
    raw = [
        ("cipher_aead_gcm_valid_encrypt_control", "success", "valid_gcm_encrypt"),
        ("cipher_aead_gcm_decrypt_without_tag_observation", "observation", "decrypt_without_tag"),
        ("cipher_aead_gcm_reset_reuse_observation", "observation", "reset_reuse"),
    ]
    return [
        {
            "case_id": case_id,
            "family": "cipher_aead_lifecycle",
            "track": "lifecycle",
            "expected_behavior": expected,
            "mutation_strategy": strategy,
            "enabled": True,
            "source": cipher_aead_case_source(case_id, expected, strategy),
        }
        for case_id, expected, strategy in raw
    ]


def cipher_aead_case_source(case_id: str, expected: str, strategy: str) -> str:
    if strategy == "valid_gcm_encrypt":
        body = """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, out, &out_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);
    ret_tag = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_tag == 1) ? "success" : "error";
"""
    elif strategy == "decrypt_without_tag":
        body = """
    ret_init = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    ret_update = EVP_DecryptUpdate(ctx, out, &out_len, plaintext, plaintext_len);
    ret_final = EVP_DecryptFinal_ex(ctx, out + out_len, &final_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    else:
        body = """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, out, &out_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, out + out_len, &final_len);
    ret_reset = EVP_CIPHER_CTX_reset(ctx);
    ret_second_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_reset == 1 && ret_second_init == 1) ? "success" : "error";
"""
    return f"""/*
 * Auto campaign EVP AEAD GCM lifecycle harness.
 * Observation cases are not vulnerability claims.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0, ret_update = 0, ret_final = 0, ret_tag = 0, ret_reset = 0, ret_second_init = 0;
    unsigned char key[16] = {{0}};
    unsigned char iv[12] = {{0}};
    unsigned char tag[16] = {{0}};
    unsigned char plaintext[] = "local gcm message";
    unsigned char out[128] = {{0}};
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL)
        goto done;
{body}
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
    printf("ORACLE_EVENT family=cipher_aead_lifecycle\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}}
"""


def build_seed_manifest(family: str, profile: dict[str, Any], cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "campaign_auto_seed_manifest_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": profile["track"],
        "archetype": profile["archetype"],
        "target_library": "openssl",
        "seed_ready": True,
        "unsafe_use_after_free_enabled": False,
        "double_free_enabled": False,
        "enabled_case_count": len([item for item in cases if item.get("enabled") is not False]),
        "seeds": [
            {
                "seed_id": item["case_id"],
                "mutation_strategy": item["mutation_strategy"],
                "expected_behavior": item["expected_behavior"],
                "enabled": item.get("enabled") is not False,
                "deferred_reason": item.get("deferred_reason", ""),
            }
            for item in cases
        ],
    }


def build_mutation_plan(family: str, profile: dict[str, Any], cases: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "campaign_auto_mutation_plan_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": profile["track"],
        "archetype": profile["archetype"],
        "mutation_case_count": len(cases),
        "enabled_case_count": len([item for item in cases if item.get("enabled") is not False]),
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "unsafe_use_after_free_executed": False,
        "cases": [
            {
                "case_id": item["case_id"],
                "mutation_strategy": item["mutation_strategy"],
                "expected_behavior": item["expected_behavior"],
                "enabled": item.get("enabled") is not False,
                "deferred_reason": item.get("deferred_reason", ""),
            }
            for item in cases
        ],
    }


def write_family_cases(base: Path, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rendered = []
    for item in cases:
        if item.get("enabled") is False:
            continue
        path = base / "cases" / f"{item['case_id']}.c"
        write_text(path, item["source"])
        rendered.append({k: v for k, v in item.items() if k != "source"} | {"path": path.as_posix()})
    return rendered


def analyze_family(
    family: str,
    profile: dict[str, Any],
    family_root: Path,
    openssl_install: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    cases = family_cases(family)
    seed_manifest = build_seed_manifest(family, profile, cases)
    mutation_plan = build_mutation_plan(family, profile, cases)
    dump_yaml(family_root / "seed_discovery/seed_manifest.yaml", seed_manifest)
    dump_yaml(family_root / "mutation/mutation_plan.yaml", mutation_plan)
    prepare_family_inputs(family, family_root)
    rendered = write_family_cases(family_root, cases)
    render_plan = {
        "schema": "campaign_auto_render_plan_v1",
        "generated_at": now_iso(),
        "family": family,
        "track": profile["track"],
        "archetype": profile["archetype"],
        "render_plan_generated": True,
        "cases": rendered,
    }
    dump_yaml(family_root / "render/render_plan.yaml", render_plan)
    dump_yaml(
        family_root / "render/render_cases_summary.yaml",
        {
            "schema": "campaign_auto_render_cases_summary_v1",
            "family": family,
            "render_cases_executed": True,
            "rendered_case_count": len(rendered),
            "uses_der_trailing_garbage": False,
            "uses_full_consumption_oracle": False,
            "unsafe_use_after_free_executed": False,
        },
    )
    compile_records, run_records, oracle_events = compile_and_run(
        rendered,
        family_root,
        openssl_install,
        timeout_seconds,
    )
    compile_success = len([item for item in compile_records if item["compile_status"] == "compile_success"])
    compile_failed = len(compile_records) - compile_success
    run_attempted = len([item for item in run_records if item["run_status"] != "not_run_compile_failed"])
    event_map = {item["case_id"]: item for item in oracle_events}
    run_map = {item["case_id"]: item for item in run_records}
    findings = [
        classify_campaign_finding(item, run_map.get(item["case_id"], {}), event_map.get(item["case_id"]))
        for item in rendered
    ]
    candidates = [item for item in findings if item["candidate"]]
    label_count = lambda label: len([item for item in findings if item["label"] == label])
    candidate_summary = {
        "schema": "campaign_auto_candidate_summary_v1",
        "candidate_queue_generated": True,
        "candidate_count": len(candidates),
        "candidate_labels": sorted(set(item["label"] for item in findings)),
        "crash_candidate_count": label_count("crash_candidate"),
        "sanitizer_candidate_count": label_count("sanitizer_candidate"),
        "unexpected_success_after_invalid_state_count": label_count(
            "unexpected_success_after_invalid_state_candidate"
        ),
        "unexpected_failure_on_valid_sequence_count": label_count(
            "unexpected_failure_on_valid_sequence_candidate"
        ),
        "semantic_divergence_count": label_count("semantic_divergence_candidate"),
        "needs_triage_count": label_count("needs_triage"),
    }
    baseline_failed = candidate_summary["unexpected_failure_on_valid_sequence_count"] > 0
    if compile_failed:
        quality_status = "blocked_compile_failure"
    elif baseline_failed:
        quality_status = "blocked_baseline_control_failed"
    elif candidates:
        quality_status = "pass_candidate_found"
    else:
        quality_status = "pass_no_candidate"
    dump_yaml(family_root / "compile/compile_jobs.yaml", {"schema": "campaign_auto_compile_jobs_v1", "compile_jobs": compile_records})
    dump_yaml(
        family_root / "compile/compile_summary.yaml",
        {
            "schema": "campaign_auto_compile_summary_v1",
            "compile_executed": True,
            "compile_success": compile_success,
            "compile_failed": compile_failed,
        },
    )
    dump_yaml(family_root / "run/run_records.yaml", {"schema": "campaign_auto_run_records_v1", "run_records": run_records})
    dump_yaml(
        family_root / "run/run_summary.yaml",
        {
            "schema": "campaign_auto_run_summary_v1",
            "run_executed": True,
            "run_attempted": run_attempted,
            "crash": candidate_summary["crash_candidate_count"],
            "sanitizer": candidate_summary["sanitizer_candidate_count"],
        },
    )
    dump_yaml(family_root / "analyze/oracle_events.yaml", {"schema": "campaign_auto_oracle_events_v1", "oracle_events": oracle_events})
    dump_yaml(
        family_root / "analyze/analyze_summary.yaml",
        {
            "schema": "campaign_auto_analyze_summary_v1",
            "oracle_analyze_executed": True,
            "oracle_events_parsed": bool(oracle_events),
            "oracle_event_count": len(oracle_events),
            "case_findings": findings,
        },
    )
    dump_yaml(
        family_root / "candidate_queue/candidates.yaml",
        {"schema": "campaign_auto_candidates_v1", "candidates": candidates, "all_findings": findings},
    )
    dump_yaml(family_root / "candidate_queue/candidate_summary.yaml", candidate_summary)
    quality = {
        "schema": "campaign_auto_family_quality_checks_v1",
        "family": family,
        "track": profile["track"],
        "archetype": profile["archetype"],
        "seed_ready": True,
        "mutation_case_count": len(cases),
        "rendered_case_count": len(rendered),
        "compile_success": compile_success,
        "run_attempted": run_attempted,
        "oracle_events": len(oracle_events),
        "candidate_count": len(candidates),
        "baseline_control_failed": baseline_failed,
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "unsafe_use_after_free_executed": False,
        "quality_status": quality_status,
    }
    dump_yaml(family_root / "validation/family_quality_checks.yaml", quality)
    return quality


def classify_campaign_finding(
    case: dict[str, Any],
    run: dict[str, Any],
    event: dict[str, Any] | None,
) -> dict[str, Any]:
    signal = str(run.get("signal") or "")
    sanitizer = bool(run.get("sanitizer_observed"))
    actual = str((event or {}).get("actual_behavior") or "")
    expected = str(case.get("expected_behavior") or "")
    semantic_mismatch = bool((event or {}).get("semantic_mismatch"))
    state_mismatch = bool((event or {}).get("state_transition_mismatch"))
    label = "no_candidate"
    reason = "behavior is expected or documented for this local oracle"
    if sanitizer or bool((event or {}).get("crash_or_sanitizer")):
        label = "sanitizer_candidate"
        reason = "sanitizer evidence observed"
    elif signal in {"SIGSEGV", "SIGABRT"}:
        label = "crash_candidate"
        reason = f"process signaled: {signal}"
    elif event is None:
        label = "needs_triage"
        reason = "missing ORACLE_EVENT"
    elif expected == "success" and actual != "success":
        label = "unexpected_failure_on_valid_sequence_candidate"
        reason = "valid control did not report success"
    elif expected == "error_or_documented" and actual == "success" and state_mismatch:
        label = "unexpected_success_after_invalid_state_candidate"
        reason = "invalid or documented-error state unexpectedly reported success"
    elif semantic_mismatch or state_mismatch:
        label = "semantic_divergence_candidate"
        reason = "explicit semantic/state mismatch was reported"
    elif expected == "semantic_equivalence" and actual != "success":
        label = "semantic_divergence_candidate"
        reason = "semantic equivalence control did not report success"
    elif expected == "observation":
        label = "state_transition_observation"
        reason = "observation-only behavior; not a candidate by itself"
    elif expected in {"error_or_documented", "success_or_documented"}:
        label = "state_transition_observation"
        reason = "documented success/error boundary; not a candidate by itself"
    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "track": case["track"],
        "expected_behavior": expected,
        "actual_behavior": actual,
        "label": label,
        "candidate": label
        in {
            "crash_candidate",
            "sanitizer_candidate",
            "unexpected_success_after_invalid_state_candidate",
            "unexpected_failure_on_valid_sequence_candidate",
            "semantic_divergence_candidate",
            "needs_triage",
        },
        "reason": reason,
        "exit_code": run.get("exit_code"),
        "signal": signal,
        "sanitizer_observed": sanitizer,
        "sanitizer_kinds": run.get("sanitizer_kinds") or [],
    }


def prepare_family_inputs(family: str, family_root: Path) -> None:
    if family not in {"ossl_store_lifecycle", "ossl_store_decoder_boundary"}:
        return
    write_text(Path("/tmp/crypto_pattern_fuzz_ossl_store_empty.txt"), "")
    write_text(
        Path("/tmp/crypto_pattern_fuzz_ossl_store_random.txt"),
        "this is plain local text, not PEM, DER, or a trailing-garbage corpus\n",
    )
    write_text(Path("/tmp/crypto_pattern_fuzz_ossl_store_unknown.ext"), "unsupported local format\n")


def stop_for(quality: dict[str, Any]) -> bool:
    return (
        int(quality.get("candidate_count") or 0) > 0
        or bool(quality.get("baseline_control_failed"))
        or quality.get("quality_status") in {"failed_der_parsing_leakage", "blocked_compile_failure"}
    )


def write_report(out_dir: Path, qc: dict[str, Any], qualities: list[dict[str, Any]], *, version: str = "v1") -> None:
    rows = "\n".join(
        f"- {item['family']}: {item['quality_status']} candidates={item['candidate_count']} "
        f"compile={item['compile_success']} run={item['run_attempted']}"
        for item in qualities
    )
    title = (
        "ccm_oracle_fix_and_resume_remaining_families_v1"
        if version == "ccm_fix_resume"
        else (
            "campaign_auto_bootstrap_loop_v3_remaining_plus_deeper_mutation"
            if version == "v3"
            else ("campaign_auto_bootstrap_loop_v2_ossl_store_first" if version == "v2" else TASK)
        )
    )
    report = f"""# {title} Report

## Summary

- quality_status: {qc.get('quality_status')}
- families_attempted: {qc.get('families_attempted')}
- candidate_found: {qc.get('candidate_found')}
- rendered_case_total: {qc.get('rendered_case_total')}
- compile_success_total: {qc.get('compile_success_total')}
- run_attempted_total: {qc.get('run_attempted_total')}

## Families

{rows}

## Policy

No tools script, public target access, exploit chain, main feedback write,
pattern-bank update, git operation, confirmed vulnerability claim, DER
trailing-garbage repeat, or full-consumption oracle was used.
"""
    name = (
        "ccm_oracle_fix_and_resume_remaining_families_v1_report.md"
        if version == "ccm_fix_resume"
        else (
            "campaign_auto_bootstrap_loop_v3_remaining_plus_deeper_mutation_report.md"
            if version == "v3"
            else (
                "campaign_auto_bootstrap_loop_v2_ossl_store_first_report.md"
                if version == "v2"
                else "campaign_auto_bootstrap_loop_v1_report.md"
            )
        )
    )
    write_text(out_dir / "reports" / name, report)


def write_ccm_oracle_fix_artifacts(repo_root: Path, out_dir: Path, triage_root: Path) -> dict[str, Any]:
    triage_decision = load_yaml(triage_root / "candidate/triage_decision.yaml")
    oracle_adjustment = load_yaml(triage_root / "feedback_to_pipeline/oracle_adjustment_recommendation.yaml")
    mutation_adjustment = load_yaml(triage_root / "feedback_to_pipeline/mutation_rule_adjustment.yaml")
    original_downgraded = triage_decision.get("decision") == "downgrade_to_observation"
    applied_oracle = {
        "schema": "ccm_oracle_adjustment_applied_v1",
        "source": (triage_root / "feedback_to_pipeline/oracle_adjustment_recommendation.yaml").as_posix(),
        "payload_only_no_length": {
            "case_type": "payload_only_without_explicit_plaintext_length",
            "expected_behavior": "observation",
            "allowed_actual_behavior": ["success", "error"],
            "candidate": False,
            "label": "state_transition_observation",
        },
        "with_aad_no_length": {
            "case_type": "with_aad_without_plaintext_length_announcement",
            "expected_behavior": "error_or_documented",
            "candidate_condition": "actual_behavior == success",
            "candidate_label": "unexpected_success_after_invalid_state_candidate",
        },
        "decrypt_invalid_state": {
            "candidate_condition": "missing tag, wrong tag, missing required length, or invalid order accepts invalid input",
            "candidate_labels": [
                "unexpected_success_after_invalid_state_candidate",
                "semantic_divergence_candidate",
            ],
        },
        "crash_or_sanitizer": {
            "ASAN_or_UBSAN": "sanitizer_candidate",
            "SIGSEGV_or_SIGABRT": "crash_candidate",
        },
    }
    applied_mutation = {
        "schema": "ccm_mutation_rule_adjustment_applied_v1",
        "source": (triage_root / "feedback_to_pipeline/mutation_rule_adjustment.yaml").as_posix(),
        "split_rule": "Split CCM no-length mutation into with_aad_required_length and payload_only_observation variants.",
        "payload_only_no_length_candidate_disabled": True,
        "with_aad_no_length_candidate_condition_enabled": True,
        "unsafe_disabled": ["use_after_free", "double_free", "self_copy"],
    }
    regression = {
        "schema": "ccm_oracle_regression_summary_v1",
        "triage_decision": triage_decision.get("decision", ""),
        "original_label": triage_decision.get("original_label", ""),
        "revised_label": "state_transition_observation" if original_downgraded else triage_decision.get("original_label", ""),
        "payload_only_no_length_candidate_disabled": True,
        "with_aad_no_length_candidate_condition_enabled": True,
        "notes": "Resume campaign skips CCM and applies the corrected oracle semantics for future CCM runs.",
    }
    dump_yaml(out_dir / "ccm_oracle_fix/triage_decision_snapshot.yaml", triage_decision)
    dump_yaml(out_dir / "ccm_oracle_fix/oracle_adjustment_applied.yaml", applied_oracle)
    dump_yaml(out_dir / "ccm_oracle_fix/mutation_rule_adjustment_applied.yaml", applied_mutation)
    dump_yaml(out_dir / "ccm_oracle_fix/ccm_oracle_regression_summary.yaml", regression)
    dump_yaml(
        repo_root / "knowledge/oracle_adjustments/cipher_aead_lifecycle_ccm.yaml",
        {
            "schema": "oracle_adjustment_v1",
            "family": "cipher_aead_lifecycle_ccm",
            "source_triage": triage_root.as_posix(),
            "decision": triage_decision.get("decision", ""),
            "payload_only_without_explicit_plaintext_length": applied_oracle["payload_only_no_length"],
            "with_aad_without_plaintext_length_announcement": applied_oracle["with_aad_no_length"],
            "main_feedback_written": False,
            "pattern_bank_modified": False,
        },
    )
    return {
        "triage_decision_loaded": bool(triage_decision),
        "ccm_original_candidate_downgraded": original_downgraded,
        "ccm_oracle_adjustment_applied": True,
        "ccm_mutation_rule_adjustment_applied": True,
        "payload_only_no_length_candidate_disabled": True,
        "with_aad_no_length_candidate_condition_enabled": True,
    }


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    manual_root = repo_root / args.manual_audit_root
    inventory_root = repo_root / args.inventory_root
    profiles_path = repo_root / args.family_profiles
    openssl_install = Path(args.openssl_install)
    version = args.campaign_version
    if version == "ccm_fix_resume":
        priority = PRIORITY_CCM_FIX_RESUME
        completed_no_candidate = COMPLETED_NO_CANDIDATE_CCM_FIX_RESUME
    elif version == "v3":
        priority = PRIORITY_V3
        completed_no_candidate = COMPLETED_NO_CANDIDATE_V3
    elif version == "v2":
        priority = PRIORITY_V2
        completed_no_candidate = COMPLETED_NO_CANDIDATE_V2
    else:
        priority = PRIORITY
        completed_no_candidate = COMPLETED_NO_CANDIDATE

    ccm_fix_status: dict[str, Any] = {}
    if version == "ccm_fix_resume":
        ccm_fix_status = write_ccm_oracle_fix_artifacts(repo_root, out_dir, repo_root / args.ccm_triage_root)

    manual_profiles = load_yaml(manual_root / "feedback_to_pipeline/proposed_family_profiles.yaml")
    inventory_profiles = load_yaml(inventory_root / "proposed_family_profiles.yaml")
    queue = queue_docs(
        repo_root,
        manual_root,
        inventory_root,
        out_dir,
        args.max_families,
        priority=priority,
        completed_no_candidate=completed_no_candidate,
    )
    dump_yaml(
        out_dir / "campaign_config.yaml",
        {
            "schema": "campaign_auto_bootstrap_loop_config_v1",
            "generated_at": now_iso(),
            "campaign_version": version,
            "max_families": args.max_families,
            "max_cases_per_family": 12 if version in {"v3", "ccm_fix_resume"} else 3,
            "deeper_mutation_enabled": version in {"v3", "ccm_fix_resume"},
            "priority_order": priority,
            "stop_on_candidate": True,
            "openssl_install": openssl_install.as_posix(),
            "ccm_triage_root": args.ccm_triage_root if version == "ccm_fix_resume" else "",
        },
    )
    dump_yaml(
        out_dir / "completed_families_snapshot.yaml",
        {
            "schema": "completed_families_snapshot_v1",
            "completed_no_candidate": completed_no_candidate,
            "known_pattern_only": KNOWN_PATTERN_ONLY,
            "historical_tested": HISTORICAL_TESTED,
            "parsing_deprioritized": PARSING_DEPRIORITIZED,
        },
    )
    dump_yaml(
        out_dir / "skipped_families.yaml",
        {
            "schema": "campaign_skipped_families_v1",
            "completed_no_candidate": completed_no_candidate,
            "known_pattern_only": KNOWN_PATTERN_ONLY,
            "historical_tested": HISTORICAL_TESTED,
            "parsing_deprioritized": PARSING_DEPRIORITIZED,
        },
    )

    qualities = []
    profile_auto_registered = 0
    card_auto_added = 0
    stop_reason = {
        "schema": "campaign_stop_reason_v1",
        "stop_reason": "max_family_budget_reached",
        "stopped_on_candidate": False,
        "stopped_on_budget": True,
        "stopped_no_ready_family": False,
        "candidate_family": "",
    }
    for family in queue:
        profile = profile_for(family, manual_profiles, inventory_profiles)
        added = register_profile(repo_root, profiles_path, family, profile)
        card_added = ensure_family_card(repo_root, family, profile)
        profile_auto_registered += 1 if added else 0
        card_auto_added += 1 if card_added else 0
        family_root = out_dir / "per_family" / family
        dump_yaml(
            family_root / "family_registration_summary.yaml",
            {
                "schema": "campaign_auto_family_registration_summary_v1",
                "family": family,
                "track": profile["track"],
                "archetype": profile["archetype"],
                "profile_auto_registered": added,
                "family_card_auto_added": card_added,
                "profile_path": args.family_profiles,
                "family_card_path": f"knowledge/family_cards/{family}.yaml",
            },
        )
        quality = analyze_family(family, profile, family_root, openssl_install, args.timeout_seconds)
        quality["profile_auto_registered"] = added
        quality["family_card_auto_added"] = card_added
        qualities.append(quality)
        if stop_for(quality):
            stop_reason = {
                "schema": "campaign_stop_reason_v1",
                "stop_reason": "candidate_or_blocking_condition",
                "stopped_on_candidate": int(quality.get("candidate_count") or 0) > 0,
                "stopped_on_budget": False,
                "stopped_no_ready_family": False,
                "candidate_family": family if int(quality.get("candidate_count") or 0) > 0 else "",
                "blocking_family": family if quality.get("quality_status") != "pass_no_candidate" else "",
            }
            break
    if not qualities:
        stop_reason = {
            "schema": "campaign_stop_reason_v1",
            "stop_reason": "no_ready_family",
            "stopped_on_candidate": False,
            "stopped_on_budget": False,
            "stopped_no_ready_family": True,
            "candidate_family": "",
        }

    candidate_found = any(int(item.get("candidate_count") or 0) > 0 for item in qualities)
    candidate_family = next((item["family"] for item in qualities if int(item.get("candidate_count") or 0) > 0), "")
    families_blocked = [item["family"] for item in qualities if str(item.get("quality_status", "")).startswith("blocked")]
    if candidate_found:
        quality_status = "pass_candidate_found"
    elif families_blocked and len(families_blocked) == len(qualities):
        quality_status = "blocked_no_ready_family"
    elif families_blocked:
        quality_status = "pass_no_candidate_some_blocked"
    else:
        quality_status = "pass_no_candidate_batch_completed"

    totals = {
        "rendered_case_total": sum(int(item.get("rendered_case_count") or 0) for item in qualities),
        "compile_success_total": sum(int(item.get("compile_success") or 0) for item in qualities),
        "run_attempted_total": sum(int(item.get("run_attempted") or 0) for item in qualities),
        "oracle_events_total": sum(int(item.get("oracle_events") or 0) for item in qualities),
    }
    mutation_case_total = sum(int(item.get("mutation_case_count") or 0) for item in qualities)
    min_cases_per_family_satisfied = all(
        int(item.get("mutation_case_count") or 0) >= 8
        and int(item.get("rendered_case_count") or 0) >= 8
        and int(item.get("compile_success") or 0) >= 8
        and int(item.get("run_attempted") or 0) >= 8
        and int(item.get("oracle_events") or 0) >= 8
        for item in qualities
    ) if qualities else False
    campaign_summary = {
        "schema": "campaign_candidate_summary_v1",
        "candidate_found": candidate_found,
        "candidate_family": candidate_family,
        "families": [
            {
                "family": item["family"],
                "candidate_count": item["candidate_count"],
                "quality_status": item["quality_status"],
            }
            for item in qualities
        ],
    }
    remaining = [item for item in priority if item not in [q["family"] for q in qualities]]
    dump_yaml(out_dir / "stop_reason.yaml", stop_reason)
    dump_yaml(out_dir / "campaign_candidate_summary.yaml", campaign_summary)
    dump_yaml(
        out_dir / "remaining_family_status.yaml",
        {
            "schema": "remaining_family_status_v1",
            "remaining_novel": remaining,
            "blocked": families_blocked,
            "needs_renderer": [] if version in {"v3", "ccm_fix_resume"} else remaining,
            "needs_api_card": [item for item in remaining if item not in {"cipher_aead_lifecycle"}],
            "external_pending": ["asn1_nested_boundary", "pkcs_container_parsing", "x509_parsing"],
        },
    )
    dump_yaml(
        out_dir / "feedback_to_pipeline/integration_backlog.yaml",
        {
            "schema": "campaign_integration_backlog_v1",
            "completed_no_candidate": [item["family"] for item in qualities if item["quality_status"] == "pass_no_candidate"],
            "next_families": remaining[:5],
            "profile_auto_registered": [item["family"] for item in qualities if item.get("profile_auto_registered")],
            "family_card_auto_added": [item["family"] for item in qualities if item.get("family_card_auto_added")],
            "main_feedback_written": False,
            "pattern_bank_modified": False,
        },
    )
    qc = {
        "schema": (
            "ccm_oracle_fix_and_resume_quality_checks_v1"
            if version == "ccm_fix_resume"
            else (
                "campaign_auto_bootstrap_loop_v3_quality_checks"
                if version == "v3"
                else (
                    "campaign_auto_bootstrap_loop_v2_quality_checks"
                    if version == "v2"
                    else "campaign_auto_bootstrap_loop_quality_checks_v1"
                )
            )
        ),
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        **ccm_fix_status,
        "inventory_loaded": bool(load_yaml(inventory_root / "family_status_matrix.yaml")),
        "manual_audit_feedback_loaded": bool(manual_profiles),
        "previous_loop_loaded": (
            (repo_root / "artifacts/campaigns/campaign_auto_bootstrap_loop_v3_remaining_plus_deeper_mutation/campaign_state.yaml").exists()
            and (repo_root / "artifacts/triage/ccm_plaintext_length_not_announced_triage_v1/candidate/triage_decision.yaml").exists()
            if version == "ccm_fix_resume"
            else (
                (repo_root / "artifacts/campaigns/campaign_auto_bootstrap_loop_v2_ossl_store_first/campaign_state.yaml").exists()
                if version == "v3"
                else (
                    (repo_root / "artifacts/campaigns/campaign_auto_bootstrap_loop_v1/campaign_state.yaml").exists()
                    if version == "v2"
                    else True
                )
            )
        ),
        "family_queue_generated": True,
        "deeper_mutation_enabled": version in {"v3", "ccm_fix_resume"},
        "completed_families_skipped": True,
        "known_pattern_families_skipped": True,
        "historical_tested_families_skipped": True,
        "parsing_track_deprioritized": True,
        "max_families": args.max_families,
        "families_attempted": len(qualities),
        "families_completed_no_candidate": len([item for item in qualities if item["quality_status"] == "pass_no_candidate"]),
        "families_blocked": len(families_blocked),
        "candidate_found": candidate_found,
        "candidate_family": candidate_family,
        "campaign_stopped_on_candidate": bool(stop_reason.get("stopped_on_candidate")),
        "ossl_store_lifecycle_attempted": any(item["family"] == "ossl_store_lifecycle" for item in qualities),
        "profile_auto_registered_count": profile_auto_registered,
        "family_card_auto_added_count": card_auto_added,
        "seed_generated_count": sum(len(family_cases(item["family"])) for item in qualities),
        "mutation_case_total": mutation_case_total,
        **totals,
        "min_cases_per_family_satisfied": min_cases_per_family_satisfied,
        "uses_der_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "unsafe_use_after_free_executed": False,
        "unsafe_uaf_or_double_free_executed": False,
        "public_target_access": False,
        "exploit_chain_generated": False,
        "api_key_logged": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }
    dump_yaml(
        out_dir / "campaign_state.yaml",
        {
            "schema": "campaign_auto_bootstrap_loop_state_v1",
            "generated_at": now_iso(),
            "families_attempted": [item["family"] for item in qualities],
            "stop_reason": stop_reason,
            "quality_status": quality_status,
        },
    )
    quality_path = (
        out_dir / "validation/ccm_oracle_fix_and_resume_quality_checks.yaml"
        if version == "ccm_fix_resume"
        else (
            out_dir / "validation/campaign_auto_bootstrap_loop_v3_quality_checks.yaml"
            if version == "v3"
            else (
                out_dir / "validation/campaign_auto_bootstrap_loop_v2_quality_checks.yaml"
                if version == "v2"
                else out_dir / "validation/campaign_auto_bootstrap_loop_quality_checks.yaml"
            )
        )
    )
    dump_yaml(quality_path, qc)
    write_report(out_dir, qc, qualities, version=version)
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality_status}")
    print(f"families_attempted: {len(qualities)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
