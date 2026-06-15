"""Build lifecycle render plans from lifecycle mutation plans."""

from __future__ import annotations

from typing import Any

from analysis.analysis_records import now_iso


def build_lifecycle_render_plan(mutation_plan: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    cases = []
    for item in mutation_plan.get("cases", []) or []:
        if item.get("enabled") is not True:
            continue
        cases.append(
            {
                "case_id": item.get("case_id"),
                "family": mutation_plan.get("family"),
                "track": mutation_plan.get("track"),
                "archetype": mutation_plan.get("archetype"),
                "target_library": mutation_plan.get("target_library"),
                "mutation_strategy": item.get("mutation_strategy"),
                "case_group": item.get("case_group"),
                "expected_behavior": item.get("expected_behavior"),
                "oracle_rule": item.get("oracle_rule"),
                "ctx_allocation": "EVP_MD_CTX_new",
                "digest": "EVP_sha256",
                "sequence": sequence_for(
                    str(item.get("mutation_strategy") or ""),
                    str(mutation_plan.get("family") or ""),
                ),
                "cleanup": ["EVP_MD_CTX_reset if ctx is allocated", "EVP_MD_CTX_free"],
                "render_mode": "lifecycle_harness",
                "uses_der_parsing": False,
                "uses_trailing_garbage": False,
                "uses_full_consumption_oracle": False,
            }
        )
    plan = {
        "schema": "lifecycle_render_plan_v1",
        "generated_at": now_iso(),
        "family": mutation_plan.get("family"),
        "track": mutation_plan.get("track"),
        "archetype": mutation_plan.get("archetype"),
        "target_library": mutation_plan.get("target_library"),
        "render_mode": "lifecycle_harness",
        "render_plan_generated": True,
        "render_case_count": len(cases),
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "cases": cases,
    }
    summary = {
        "schema": "lifecycle_render_summary_v1",
        "generated_at": now_iso(),
        "family": mutation_plan.get("family"),
        "render_plan_generated": True,
        "render_case_count": len(cases),
        "render_mode": "lifecycle_harness",
    }
    deferred = {
        "schema": "lifecycle_deferred_render_capabilities_v1",
        "generated_at": now_iso(),
        "family": mutation_plan.get("family"),
        "deferred": [
            {
                "capability": "unsafe_use_after_free_harness",
                "enabled": False,
                "reason": "unsafe negative control is metadata only and is not rendered by default",
            }
        ],
    }
    return plan, summary, deferred


def sequence_for(strategy: str, family: str = "") -> list[str]:
    if family == "mac_lifecycle":
        return mac_sequence_for(strategy)
    if family == "evp_cipher_ctx_lifecycle":
        return cipher_sequence_for(strategy)
    common = [
        "ctx = EVP_MD_CTX_new()",
        "message = fixed byte string",
    ]
    if strategy == "valid_init_update_final_control":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    if strategy == "update_before_init":
        return common + ["EVP_DigestUpdate(ctx, message, message_len)"]
    if strategy == "final_without_update":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    if strategy == "update_after_final":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
            "EVP_DigestUpdate(ctx, message, message_len)",
        ]
    if strategy == "reset_reuse":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
            "EVP_MD_CTX_reset(ctx)",
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    if strategy == "reinit_without_reset":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    if strategy == "double_final":
        return common + [
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    if strategy == "reset_before_init":
        return common + [
            "EVP_MD_CTX_reset(ctx)",
            "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)",
            "EVP_DigestUpdate(ctx, message, message_len)",
            "EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len)",
        ]
    return common


def mac_sequence_for(strategy: str) -> list[str]:
    common = [
        'mac = EVP_MAC_fetch(NULL, "HMAC", NULL)',
        "ctx = EVP_MAC_CTX_new(mac)",
        'params = digest=SHA256',
        "key = fixed byte string",
        "message = fixed byte string",
    ]
    if strategy == "valid_hmac_init_update_final_control":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
        ]
    if strategy == "update_before_init":
        return common + ["EVP_MAC_update(ctx, message, message_len)"]
    if strategy == "final_without_update_after_init":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
        ]
    if strategy == "repeated_final":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
            "EVP_MAC_final(ctx, mac_out_2, &mac_out_len_2, sizeof(mac_out_2))",
        ]
    if strategy == "update_after_final":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
            "EVP_MAC_update(ctx, message, message_len)",
        ]
    if strategy == "reinit_reuse":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out_2, &mac_out_len_2, sizeof(mac_out_2))",
        ]
    if strategy == "wrong_key_length_observation":
        return common + [
            "EVP_MAC_init(ctx, empty_key, 0, params)",
            "EVP_MAC_update(ctx, message, message_len)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
        ]
    if strategy == "empty_message_observation":
        return common + [
            "EVP_MAC_init(ctx, key, key_len, params)",
            "EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out))",
        ]
    return common


def cipher_sequence_for(strategy: str) -> list[str]:
    common = ["ctx = EVP_CIPHER_CTX_new()", "cipher = EVP_aes_128_cbc()", "plaintext = fixed byte string"]
    if strategy == "valid_init_update_final_control":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
        ]
    if strategy == "update_before_init":
        return common + ["EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)"]
    if strategy == "final_without_update":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptFinal_ex(ctx, ciphertext, &final_len)",
        ]
    if strategy == "update_after_final":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
        ]
    if strategy == "reset_reuse":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
            "EVP_CIPHER_CTX_reset(ctx)",
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
        ]
    if strategy == "reinit_without_reset":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
        ]
    if strategy == "double_final":
        return common + [
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len + final_len, &second_final_len)",
        ]
    if strategy == "reset_before_init":
        return common + [
            "EVP_CIPHER_CTX_reset(ctx)",
            "EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)",
            "EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len)",
            "EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len)",
        ]
    return common
