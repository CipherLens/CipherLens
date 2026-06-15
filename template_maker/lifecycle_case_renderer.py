"""Render lifecycle C harnesses from lifecycle render plans."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from analysis.analysis_records import now_iso, write_text


def c_ident(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", text)


def render_lifecycle_cases(render_plan: dict[str, Any], out_dir: Path, repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    cases_dir = out_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    case_files = []
    for case in render_plan.get("cases", []) or []:
        path = cases_dir / f"{case['case_id']}.c"
        write_text(path, harness_source(case))
        case_files.append(
            {
                "case_id": case.get("case_id"),
                "path": path.relative_to(repo_root).as_posix(),
                "expected_behavior": case.get("expected_behavior"),
                "mutation_strategy": case.get("mutation_strategy"),
                "case_group": case.get("case_group"),
                "oracle_rule": case.get("oracle_rule"),
            }
        )
    summary = {
        "schema": "lifecycle_render_cases_summary_v1",
        "generated_at": now_iso(),
        "family": render_plan.get("family"),
        "track": render_plan.get("track"),
        "archetype": render_plan.get("archetype"),
        "target_library": render_plan.get("target_library"),
        "render_cases_executed": True,
        "rendered_case_count": len(case_files),
        "uses_der_parsing": False,
        "uses_trailing_garbage": False,
        "uses_full_consumption_oracle": False,
        "unsafe_use_after_free_executed": False,
        "case_files": case_files,
    }
    records = {
        "schema": "lifecycle_render_records_v1",
        "generated_at": now_iso(),
        "family": render_plan.get("family"),
        "render_records": [
            {
                **item,
                "render_status": "rendered",
                "compile_executed": False,
                "run_executed": False,
            }
            for item in case_files
        ],
    }
    return summary, records


def c_statement_block(strategy: str) -> str:
    if strategy == "valid_init_update_final_control":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "update_before_init":
        return """
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    actual_behavior = (ret_update == 1) ? "success" : "error";
"""
    if strategy == "final_without_update":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    actual_behavior = (ret_init == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "update_after_final":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    ret_after = EVP_DigestUpdate(ctx, message, message_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_after == 1) ? "success" : "error";
"""
    if strategy == "reset_reuse":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    ret_reset = EVP_MD_CTX_reset(ctx);
    ret_second_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_second_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_second_final = EVP_DigestFinal_ex(ctx, digest_out_2, &digest_out_len_2);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_reset == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "reinit_without_reset":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    ret_second_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_second_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_second_final = EVP_DigestFinal_ex(ctx, digest_out_2, &digest_out_len_2);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "double_final":
        return """
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    ret_second_final = EVP_DigestFinal_ex(ctx, digest_out_2, &digest_out_len_2);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "reset_before_init":
        return """
    ret_reset = EVP_MD_CTX_reset(ctx);
    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    actual_behavior = (ret_reset == 1 && ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    return """
    actual_behavior = "error";
"""


def cipher_statement_block(strategy: str) -> str:
    if strategy == "valid_init_update_final_control":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "update_before_init":
        return """
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    actual_behavior = (ret_update == 1) ? "success" : "error";
"""
    if strategy == "final_without_update":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext, &final_len);
    actual_behavior = (ret_init == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "update_after_final":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ret_after = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_after == 1) ? "success" : "error";
"""
    if strategy == "reset_reuse":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ret_reset = EVP_CIPHER_CTX_reset(ctx);
    ciphertext_len = 0;
    final_len = 0;
    ret_second_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_second_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_second_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &second_final_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_reset == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "reinit_without_reset":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ret_second_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_second_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_second_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &second_final_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "double_final":
        return """
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ret_second_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len + final_len, &second_final_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "reset_before_init":
        return """
    ret_reset = EVP_CIPHER_CTX_reset(ctx);
    ret_init = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    ret_final = EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    actual_behavior = (ret_reset == 1 && ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    return """
    actual_behavior = "error";
"""


def mac_statement_block(strategy: str) -> str:
    if strategy == "valid_hmac_init_update_final_control":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_update = EVP_MAC_update(ctx, message, message_len);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "update_before_init":
        return """
    ret_update = EVP_MAC_update(ctx, message, message_len);
    actual_behavior = (ret_update == 1) ? "success" : "error";
"""
    if strategy == "final_without_update_after_init":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    actual_behavior = (ret_init == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "repeated_final":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_update = EVP_MAC_update(ctx, message, message_len);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    ret_second_final = EVP_MAC_final(ctx, mac_out_2, &mac_out_len_2, sizeof(mac_out_2));
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "update_after_final":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_update = EVP_MAC_update(ctx, message, message_len);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    ret_after = EVP_MAC_update(ctx, message, message_len);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 && ret_after == 1) ? "success" : "error";
"""
    if strategy == "reinit_reuse":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_update = EVP_MAC_update(ctx, message, message_len);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    ret_second_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_second_update = EVP_MAC_update(ctx, message, message_len);
    ret_second_final = EVP_MAC_final(ctx, mac_out_2, &mac_out_len_2, sizeof(mac_out_2));
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";
"""
    if strategy == "wrong_key_length_observation":
        return """
    ret_init = EVP_MAC_init(ctx, empty_key, 0, params);
    ret_update = EVP_MAC_update(ctx, message, message_len);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1) ? "success" : "error";
"""
    if strategy == "empty_message_observation":
        return """
    ret_init = EVP_MAC_init(ctx, key, key_len, params);
    ret_final = EVP_MAC_final(ctx, mac_out, &mac_out_len, sizeof(mac_out));
    actual_behavior = (ret_init == 1 && ret_final == 1) ? "success" : "error";
"""
    return """
    actual_behavior = "error";
"""


def mismatch_rule(expected: str, oracle_rule: str) -> str:
    if oracle_rule == "unexpected_failure_on_valid_sequence":
        return 'state_transition_mismatch = strcmp(actual_behavior, "success") != 0;'
    if oracle_rule == "unexpected_success_after_invalid_state":
        return 'state_transition_mismatch = strcmp(actual_behavior, "success") == 0;'
    return "state_transition_mismatch = 0;"


def harness_source(case: dict[str, Any]) -> str:
    case_id = str(case.get("case_id"))
    strategy = str(case.get("mutation_strategy"))
    expected = str(case.get("expected_behavior"))
    oracle_rule = str(case.get("oracle_rule"))
    ident = c_ident(case_id)
    family = str(case.get("family") or "")
    if family == "mac_lifecycle":
        return mac_harness_source(case, ident)
    if family == "evp_cipher_ctx_lifecycle":
        return cipher_harness_source(case, ident)
    return f"""/*
 * Generated from lifecycle_render_plan_v1 for evp_digest_ctx_lifecycle.
 * This is an EVP_MD_CTX lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static const unsigned char message[] = "fixed digest lifecycle message";

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0;
    int ret_update = 0;
    int ret_final = 0;
    int ret_reset = 0;
    int ret_after = 0;
    int ret_second_init = 0;
    int ret_second_update = 0;
    int ret_second_final = 0;
    unsigned char digest_out[EVP_MAX_MD_SIZE];
    unsigned char digest_out_2[EVP_MAX_MD_SIZE];
    unsigned int digest_out_len = 0;
    unsigned int digest_out_len_2 = 0;
    size_t message_len = sizeof(message) - 1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        goto done;
{c_statement_block(strategy)}
    {mismatch_rule(expected, oracle_rule)}

done:
    printf("ORACLE_EVENT family=evp_digest_ctx_lifecycle\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy={strategy}\\n");
    printf("ORACLE_EVENT oracle_rule={oracle_rule}\\n");

    if (ctx != NULL)
        EVP_MD_CTX_reset(ctx);
    EVP_MD_CTX_free(ctx);
    return state_transition_mismatch ? 10 : 0;
}}

/* case symbol marker: {ident} */
"""


def mac_harness_source(case: dict[str, Any], ident: str) -> str:
    case_id = str(case.get("case_id"))
    strategy = str(case.get("mutation_strategy"))
    expected = str(case.get("expected_behavior"))
    oracle_rule = str(case.get("oracle_rule"))
    return f"""/*
 * Generated from lifecycle_render_plan_v1 for mac_lifecycle.
 * This is an EVP_MAC HMAC lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static const unsigned char key[] = {{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
}};
static const unsigned char empty_key[] = {{ 0x00 }};
static const unsigned char message[] = "fixed mac lifecycle message";

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0;
    int ret_update = 0;
    int ret_final = 0;
    int ret_after = 0;
    int ret_second_init = 0;
    int ret_second_update = 0;
    int ret_second_final = 0;
    unsigned char mac_out[EVP_MAX_MD_SIZE];
    unsigned char mac_out_2[EVP_MAX_MD_SIZE];
    size_t mac_out_len = 0;
    size_t mac_out_len_2 = 0;
    size_t key_len = sizeof(key);
    size_t message_len = sizeof(message) - 1;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[] = {{
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end()
    }};
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;

    memset(mac_out, 0, sizeof(mac_out));
    memset(mac_out_2, 0, sizeof(mac_out_2));
    if (mac == NULL)
        goto done;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto done;
{mac_statement_block(strategy)}
    {mismatch_rule(expected, oracle_rule)}

done:
    printf("ORACLE_EVENT family=mac_lifecycle\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy={strategy}\\n");
    printf("ORACLE_EVENT oracle_rule={oracle_rule}\\n");

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return state_transition_mismatch ? 10 : 0;
}}

/* case symbol marker: {ident} */
"""


def cipher_harness_source(case: dict[str, Any], ident: str) -> str:
    case_id = str(case.get("case_id"))
    strategy = str(case.get("mutation_strategy"))
    expected = str(case.get("expected_behavior"))
    oracle_rule = str(case.get("oracle_rule"))
    family = str(case.get("family") or "evp_cipher_ctx_lifecycle")
    return f"""/*
 * Generated from lifecycle_render_plan_v1 for {family}.
 * This is an EVP_CIPHER_CTX lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static const unsigned char plaintext[] = "fixed cipher lifecycle message block";
static const unsigned char key[16] = {{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
}};
static const unsigned char iv[16] = {{
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
}};

int main(void)
{{
    const char *case_id = "{case_id}";
    const char *expected_behavior = "{expected}";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0;
    int ret_update = 0;
    int ret_final = 0;
    int ret_reset = 0;
    int ret_after = 0;
    int ret_second_init = 0;
    int ret_second_update = 0;
    int ret_second_final = 0;
    int ciphertext_len = 0;
    int final_len = 0;
    int second_final_len = 0;
    int plaintext_len = (int)(sizeof(plaintext) - 1);
    unsigned char ciphertext[128];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    memset(ciphertext, 0, sizeof(ciphertext));
    if (ctx == NULL)
        goto done;
{cipher_statement_block(strategy)}
    {mismatch_rule(expected, oracle_rule)}

done:
    printf("ORACLE_EVENT family={family}\\n");
    printf("ORACLE_EVENT case_id=%s\\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy={strategy}\\n");
    printf("ORACLE_EVENT oracle_rule={oracle_rule}\\n");

    if (ctx != NULL)
        EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return state_transition_mismatch ? 10 : 0;
}}

/* case symbol marker: {ident} */
"""
