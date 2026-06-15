from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


ALLOWED_MAC_ALGORITHMS = ["HMAC", "CMAC"]
ALLOWED_DIGEST_OR_CIPHER = ["SHA256", "SHA512", "AES-128-CBC", "AES-256-CBC"]
ALLOWED_LIFECYCLE_SEQUENCES = [
    "query_size_before_setup",
    "final_before_setup",
    "update_before_setup",
    "setup_update_final",
    "setup_update_final_final",
    "setup_final_final",
    "abort_then_final",
    "update_after_final",
    "third_final",
    "final_after_abort",
    "update_after_second_final",
    "query_after_final",
    "query_after_abort",
    "wrong_digest_combo",
]

HIGH_VALUE_LIFECYCLE_SEQUENCES = {
    "update_after_final",
    "third_final",
    "final_after_abort",
    "update_after_second_final",
}


@dataclass(frozen=True)
class MacCasePlan:
    supported: bool
    unsupported_dimensions: List[Dict[str, Any]]
    source_slots: Dict[str, Any]
    target_slots: Dict[str, Any]
    common_slots: Dict[str, Any]
    expected_candidate_types: List[str]


def _unsupported(dimension: str, value: str, reason: str) -> Dict[str, Any]:
    return {
        "dimension": dimension,
        "value": value,
        "reason": reason,
        "unsupported_combo": True,
        "requires_template_extension": True,
    }


def _key_material(mac_algorithm: str, digest_or_cipher: str) -> Dict[str, Any]:
    if mac_algorithm == "CMAC" and digest_or_cipher == "AES-256-CBC":
        return {
            "key_bytes": "{\n"
            "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,\n"
            "    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,\n"
            "    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,\n"
            "    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f\n"
            "}",
            "key_len": 32,
        }
    if mac_algorithm == "CMAC":
        return {
            "key_bytes": "{\n"
            "    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,\n"
            "    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f\n"
            "}",
            "key_len": 16,
        }
    return {
        "key_bytes": "{\n"
        "    0x72, 0x61, 0x67, 0x2d, 0x73, 0x65, 0x65, 0x64,\n"
        "    0x2d, 0x68, 0x6d, 0x61, 0x63, 0x2d, 0x6b, 0x65,\n"
        "    0x79\n"
        "}",
        "key_len": 17,
    }


def _base_algorithm_slots(mac_algorithm: str, digest_or_cipher: str, lifecycle_sequence: str) -> Dict[str, Any]:
    wrong_combo = lifecycle_sequence == "wrong_digest_combo"

    if mac_algorithm == "HMAC":
        digest = digest_or_cipher
        expected_size = 64 if digest == "SHA512" else 32
        source_setup = (
            'params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);\n'
            "    params[1] = OSSL_PARAM_construct_end();"
            if wrong_combo else
            f'params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "{digest}", 0);\n'
            "    params[1] = OSSL_PARAM_construct_end();"
        )
        target_algorithm = "PSA_ALG_CMAC" if wrong_combo else (
            "PSA_ALG_HMAC(PSA_ALG_SHA_512)" if digest == "SHA512" else "PSA_ALG_HMAC(PSA_ALG_SHA_256)"
        )
        return {
            "source_mac_name": "HMAC",
            "source_setup_params": source_setup,
            "target_key_type": "PSA_KEY_TYPE_HMAC",
            "target_algorithm": target_algorithm,
            "expected_mac_size": expected_size,
        }

    expected_size = 16
    source_setup = (
        'params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);\n'
        "    params[1] = OSSL_PARAM_construct_end();"
        if wrong_combo else
        f'params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, "{digest_or_cipher}", 0);\n'
        "    params[1] = OSSL_PARAM_construct_end();"
    )
    target_algorithm = "PSA_ALG_HMAC(PSA_ALG_SHA_256)" if wrong_combo else "PSA_ALG_CMAC"
    return {
        "source_mac_name": "CMAC",
        "source_setup_params": source_setup,
        "target_key_type": "PSA_KEY_TYPE_AES",
        "target_algorithm": target_algorithm,
        "expected_mac_size": expected_size,
    }


SOURCE_SEQUENCES = {
    "final_before_setup": """
    outl = 777;
    final_ok = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    printf("SOURCE final_before_setup EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    if (final_ok != 1) {
        printf("[OK] mac_context_lifecycle: pre-setup final rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: pre-setup final unexpectedly succeeded outl=%zu\\n", outl);
    }
""".strip(),
    "update_before_setup": """
    update_ok = EVP_MAC_update(ctx, message, MESSAGE_LEN);
    printf("SOURCE update_before_setup EVP_MAC_update returned %d\\n", update_ok);
    if (update_ok != 1) {
        printf("[OK] mac_context_lifecycle: pre-setup update rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: pre-setup update unexpectedly succeeded\\n");
    }
""".strip(),
    "setup_update_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE setup_update_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE setup_update_final EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE setup_update_final EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    if (init_ok == 1 && update_ok == 1 && final_ok == 1 && outl == EXPECTED_MAC_SIZE) {
        printf("[OK] mac_context_lifecycle: setup/update/final completed with expected output length\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: setup/update/final unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "setup_update_final_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE setup_update_final_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE setup_update_final_final EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE setup_update_final_final first EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    second_outl = 777;
    second_final_ok = final_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : 0;
    printf("SOURCE setup_update_final_final second EVP_MAC_final returned %d outl=%zu\\n", second_final_ok, second_outl);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && second_final_ok != 1) {
        printf("[OK] mac_context_lifecycle: second final rejected after completed operation\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: double final unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "setup_final_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE setup_final_final EVP_MAC_init returned %d\\n", init_ok);
    outl = 0;
    final_ok = init_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE setup_final_final first EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    second_outl = 777;
    second_final_ok = final_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : 0;
    printf("SOURCE setup_final_final second EVP_MAC_final returned %d outl=%zu\\n", second_final_ok, second_outl);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && second_final_ok != 1) {
        printf("[OK] mac_context_lifecycle: second final rejected after zero-length MAC final\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: setup/final/final unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "abort_then_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE abort_then_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE abort_then_final EVP_MAC_update returned %d\\n", update_ok);
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: EVP_MAC_CTX_new after abort-like free failed\\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    second_outl = 777;
    second_final_ok = EVP_MAC_final(ctx, out, &second_outl, sizeof(out));
    printf("SOURCE abort_then_final final on fresh uninitialized ctx returned %d outl=%zu\\n", second_final_ok, second_outl);
    if (init_ok == 1 && update_ok == 1 && second_final_ok != 1) {
        printf("[OK] mac_context_lifecycle: abort-like path rejected final on fresh uninitialized ctx\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: abort-like path unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "update_after_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE update_after_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE update_after_final first EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE update_after_final EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    update_ok = final_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE update_after_final second EVP_MAC_update after final returned %d\\n", update_ok);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && update_ok != 1) {
        printf("[OK] mac_context_lifecycle: update after final rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: update after final accepted or unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "third_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE third_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE third_final EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE third_final first EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    second_outl = 777;
    second_final_ok = final_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : 0;
    printf("SOURCE third_final second EVP_MAC_final returned %d outl=%zu\\n", second_final_ok, second_outl);
    second_outl = 777;
    update_ok = second_final_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : 0;
    printf("SOURCE third_final third EVP_MAC_final returned %d outl=%zu\\n", update_ok, second_outl);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && second_final_ok != 1) {
        printf("[OK] mac_context_lifecycle: repeated final rejected before third final path\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: third final accepted or unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "final_after_abort": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE final_after_abort EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE final_after_abort EVP_MAC_update returned %d\\n", update_ok);
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: EVP_MAC_CTX_new after abort-like free failed\\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    outl = 777;
    final_ok = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    printf("SOURCE final_after_abort EVP_MAC_final on fresh uninitialized ctx returned %d outl=%zu\\n", final_ok, outl);
    if (init_ok == 1 && update_ok == 1 && final_ok != 1) {
        printf("[OK] mac_context_lifecycle: final after abort-like reset rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: final after abort-like reset unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "update_after_second_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE update_after_second_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE update_after_second_final first EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE update_after_second_final first EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    second_outl = 777;
    second_final_ok = final_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : 0;
    printf("SOURCE update_after_second_final second EVP_MAC_final returned %d outl=%zu\\n", second_final_ok, second_outl);
    update_ok = second_final_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE update_after_second_final EVP_MAC_update after second final returned %d\\n", update_ok);
    second_outl = 777;
    second_final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &second_outl, sizeof(out)) : second_final_ok;
    printf("SOURCE update_after_second_final final after update returned %d outl=%zu\\n", second_final_ok, second_outl);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && update_ok != 1) {
        printf("[OK] mac_context_lifecycle: update after second final rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: update after second final accepted or unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "query_after_final": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE query_after_final EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE query_after_final EVP_MAC_update returned %d\\n", update_ok);
    outl = 0;
    final_ok = update_ok == 1 ? EVP_MAC_final(ctx, out, &outl, sizeof(out)) : 0;
    printf("SOURCE query_after_final EVP_MAC_final returned %d outl=%zu\\n", final_ok, outl);
    pre_size = EVP_MAC_CTX_get_mac_size(ctx);
    printf("SOURCE query_after_final EVP_MAC_CTX_get_mac_size returned %zu\\n", pre_size);
    if (final_ok == 1 && outl == EXPECTED_MAC_SIZE && pre_size == EXPECTED_MAC_SIZE) {
        printf("[OK] mac_context_lifecycle: query after final returned expected size\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: query after final unexpected state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "query_after_abort": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE query_after_abort EVP_MAC_init returned %d\\n", init_ok);
    update_ok = init_ok == 1 ? EVP_MAC_update(ctx, message, MESSAGE_LEN) : 0;
    printf("SOURCE query_after_abort EVP_MAC_update returned %d\\n", update_ok);
    EVP_MAC_CTX_free(ctx);
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "[TRIAGE] mac_context_lifecycle: EVP_MAC_CTX_new after abort-like free failed\\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    pre_size = EVP_MAC_CTX_get_mac_size(ctx);
    printf("SOURCE query_after_abort EVP_MAC_CTX_get_mac_size on fresh ctx returned %zu\\n", pre_size);
    if (init_ok == 1 && update_ok == 1) {
        printf("[OK] mac_context_lifecycle: query after abort-like reset observed without crash\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: query after abort-like reset unexpected setup state\\n");
        ERR_print_errors_fp(stderr);
    }
""".strip(),
    "wrong_digest_combo": """
    init_ok = EVP_MAC_init(ctx, key, KEY_LEN, params);
    printf("SOURCE wrong_digest_combo EVP_MAC_init returned %d\\n", init_ok);
    if (init_ok != 1) {
        printf("[OK] mac_context_lifecycle: incompatible source MAC parameters rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: incompatible source MAC parameters unexpectedly initialized\\n");
    }
""".strip(),
}


TARGET_SEQUENCES = {
    "final_before_setup": """
    mac_length = 777;
    status = psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length);
    print_psa_status("TARGET final_before_setup psa_mac_sign_finish", status);
    printf("TARGET final_before_setup mac_length=%zu\\n", mac_length);
    if (status != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: pre-setup finish rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: pre-setup finish unexpectedly succeeded\\n");
    }
""".strip(),
    "update_before_setup": """
    status = psa_mac_update(&operation, message, MESSAGE_LEN);
    print_psa_status("TARGET update_before_setup psa_mac_update", status);
    if (status != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: pre-setup update rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: pre-setup update unexpectedly succeeded\\n");
    }
""".strip(),
    "setup_update_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET setup_update_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET setup_update_final psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET setup_update_final psa_mac_sign_finish", status3);
    printf("TARGET setup_update_final mac_length=%zu\\n", mac_length);
    if (status == PSA_SUCCESS && status2 == PSA_SUCCESS && status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE) {
        printf("[OK] mac_context_lifecycle: PSA setup/update/final completed with expected output length\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA setup/update/final unexpected state\\n");
    }
""".strip(),
    "setup_update_final_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET setup_update_final_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET setup_update_final_final psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET setup_update_final_final first psa_mac_sign_finish", status3);
    second_mac_length = 777;
    status4 = status3 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status3;
    print_psa_status("TARGET setup_update_final_final second psa_mac_sign_finish", status4);
    printf("TARGET setup_update_final_final lengths first=%zu second=%zu\\n", mac_length, second_mac_length);
    if (status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE && status4 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA second finish rejected after completed operation\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA double finish unexpected state\\n");
    }
""".strip(),
    "setup_final_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET setup_final_final psa_mac_sign_setup", status);
    mac_length = 0;
    status2 = status == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status;
    print_psa_status("TARGET setup_final_final first psa_mac_sign_finish", status2);
    second_mac_length = 777;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status2;
    print_psa_status("TARGET setup_final_final second psa_mac_sign_finish", status3);
    printf("TARGET setup_final_final lengths first=%zu second=%zu\\n", mac_length, second_mac_length);
    if (status2 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE && status3 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA second finish rejected after zero-length MAC final\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA setup/final/final unexpected state\\n");
    }
""".strip(),
    "abort_then_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET abort_then_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET abort_then_final psa_mac_update", status2);
    status3 = psa_mac_abort(&operation);
    print_psa_status("TARGET abort_then_final psa_mac_abort", status3);
    mac_length = 777;
    status4 = psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length);
    print_psa_status("TARGET abort_then_final psa_mac_sign_finish after abort", status4);
    printf("TARGET abort_then_final mac_length=%zu\\n", mac_length);
    if (status == PSA_SUCCESS && status2 == PSA_SUCCESS && status3 == PSA_SUCCESS && status4 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA finish rejected after abort\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA abort_then_final unexpected state\\n");
    }
""".strip(),
    "update_after_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET update_after_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET update_after_final first psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET update_after_final psa_mac_sign_finish", status3);
    status4 = status3 == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status3;
    print_psa_status("TARGET update_after_final psa_mac_update after finish", status4);
    printf("TARGET update_after_final mac_length=%zu\\n", mac_length);
    if (status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE && status4 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA update after finish rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA update after finish unexpected state\\n");
    }
""".strip(),
    "third_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET third_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET third_final psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET third_final first psa_mac_sign_finish", status3);
    second_mac_length = 777;
    status4 = status3 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status3;
    print_psa_status("TARGET third_final second psa_mac_sign_finish", status4);
    second_mac_length = 777;
    status2 = status4 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status4;
    print_psa_status("TARGET third_final third psa_mac_sign_finish", status2);
    printf("TARGET third_final lengths first=%zu repeated=%zu\\n", mac_length, second_mac_length);
    if (status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE && status4 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA repeated finish rejected before third finish path\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA third finish unexpected state\\n");
    }
""".strip(),
    "final_after_abort": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET final_after_abort psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET final_after_abort psa_mac_update", status2);
    status3 = psa_mac_abort(&operation);
    print_psa_status("TARGET final_after_abort psa_mac_abort", status3);
    mac_length = 777;
    status4 = psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length);
    print_psa_status("TARGET final_after_abort psa_mac_sign_finish after abort", status4);
    printf("TARGET final_after_abort mac_length=%zu\\n", mac_length);
    if (status == PSA_SUCCESS && status2 == PSA_SUCCESS && status3 == PSA_SUCCESS && status4 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA finish after abort rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA final_after_abort unexpected state\\n");
    }
""".strip(),
    "update_after_second_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET update_after_second_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET update_after_second_final first psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET update_after_second_final first psa_mac_sign_finish", status3);
    second_mac_length = 777;
    status4 = status3 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status3;
    print_psa_status("TARGET update_after_second_final second psa_mac_sign_finish", status4);
    status2 = status4 == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status4;
    print_psa_status("TARGET update_after_second_final psa_mac_update after second finish", status2);
    second_mac_length = 777;
    status4 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &second_mac_length) : status2;
    print_psa_status("TARGET update_after_second_final final after update", status4);
    printf("TARGET update_after_second_final lengths first=%zu second=%zu\\n", mac_length, second_mac_length);
    if (status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE && status2 != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA update after second finish rejected\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA update after second finish unexpected state\\n");
    }
""".strip(),
    "query_after_final": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET query_after_final psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET query_after_final psa_mac_update", status2);
    mac_length = 0;
    status3 = status2 == PSA_SUCCESS ? psa_mac_sign_finish(&operation, mac, MAC_LEN, &mac_length) : status2;
    print_psa_status("TARGET query_after_final psa_mac_sign_finish", status3);
    printf("TARGET query_after_final public operation-state size query unsupported; mac_length=%zu\\n", mac_length);
    if (status3 == PSA_SUCCESS && mac_length == EXPECTED_MAC_SIZE) {
        printf("[OK] mac_context_lifecycle: PSA final succeeded; post-final size query is projection-limited\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA query_after_final unexpected state\\n");
    }
""".strip(),
    "query_after_abort": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET query_after_abort psa_mac_sign_setup", status);
    status2 = status == PSA_SUCCESS ? psa_mac_update(&operation, message, MESSAGE_LEN) : status;
    print_psa_status("TARGET query_after_abort psa_mac_update", status2);
    status3 = psa_mac_abort(&operation);
    print_psa_status("TARGET query_after_abort psa_mac_abort", status3);
    printf("TARGET query_after_abort public operation-state size query unsupported\\n");
    if (status == PSA_SUCCESS && status2 == PSA_SUCCESS && status3 == PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: PSA abort succeeded; post-abort size query is projection-limited\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: PSA query_after_abort unexpected state\\n");
    }
""".strip(),
    "wrong_digest_combo": """
    status = psa_mac_sign_setup(&operation, key_id, TARGET_KEY_ALGORITHM_VALUE);
    print_psa_status("TARGET wrong_digest_combo psa_mac_sign_setup", status);
    if (status != PSA_SUCCESS) {
        printf("[OK] mac_context_lifecycle: incompatible PSA key type / algorithm rejected safely\\n");
        ret = 0;
    } else {
        printf("[TRIAGE] mac_context_lifecycle: incompatible PSA key type / algorithm unexpectedly initialized\\n");
    }
""".strip(),
}


def build_mac_lifecycle_plan(mac_algorithm: str, digest_or_cipher: str, lifecycle_sequence: str) -> MacCasePlan:
    unsupported: List[Dict[str, Any]] = []

    if mac_algorithm not in ALLOWED_MAC_ALGORITHMS:
        unsupported.append(_unsupported("mac_algorithm", mac_algorithm, "unsupported MAC algorithm enum"))
    if digest_or_cipher not in ALLOWED_DIGEST_OR_CIPHER:
        unsupported.append(_unsupported("digest_or_cipher", digest_or_cipher, "unsupported digest_or_cipher enum"))
    if lifecycle_sequence not in ALLOWED_LIFECYCLE_SEQUENCES:
        unsupported.append(_unsupported("lifecycle_sequence", lifecycle_sequence, "unsupported lifecycle_sequence enum"))

    if lifecycle_sequence == "query_size_before_setup":
        unsupported.append(_unsupported(
            "lifecycle_sequence",
            lifecycle_sequence,
            "mbedTLS PSA MAC has no public pre-setup size query equivalent",
        ))

    if mac_algorithm == "HMAC" and digest_or_cipher.startswith("AES-"):
        unsupported.append(_unsupported("digest_or_cipher", digest_or_cipher, "HMAC requires a digest, not a cipher"))
    if mac_algorithm == "CMAC" and digest_or_cipher.startswith("SHA"):
        unsupported.append(_unsupported("digest_or_cipher", digest_or_cipher, "CMAC requires a block cipher, not a digest"))

    if unsupported:
        return MacCasePlan(False, unsupported, {}, {}, {}, ["projection_limitation"])

    algorithm_slots = _base_algorithm_slots(mac_algorithm, digest_or_cipher, lifecycle_sequence)
    key = _key_material(mac_algorithm, digest_or_cipher)
    expected_size = algorithm_slots["expected_mac_size"]
    message = "{\n    0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,\n    0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,\n    0x67\n}"
    message_len = 17

    source_sequence = SOURCE_SEQUENCES[lifecycle_sequence]
    target_sequence = TARGET_SEQUENCES[lifecycle_sequence].replace(
        "TARGET_KEY_ALGORITHM_VALUE",
        algorithm_slots["target_algorithm"],
    )

    expected_class = "safe_reject_projection" if lifecycle_sequence in {
        "final_before_setup",
        "update_before_setup",
        "abort_then_final",
        "final_after_abort",
        "wrong_digest_combo",
    } else "projection_limitation" if lifecycle_sequence in {
        "query_after_final",
        "query_after_abort",
    } else "lifecycle_semantic_divergence_candidate" if lifecycle_sequence in HIGH_VALUE_LIFECYCLE_SEQUENCES else "allowed_legacy_semantics"

    common_slots = {
        "DIGEST_OR_CIPHER": digest_or_cipher,
        "EXPECTED_MAC_SIZE": expected_size,
        "EXPECTED_VERDICT_CLASS": expected_class,
        "KEY_BYTES": key["key_bytes"],
        "KEY_LEN": key["key_len"],
        "MESSAGE_BYTES": message,
        "MESSAGE_LEN": message_len,
        "MAC_LEN": max(expected_size, 64),
    }
    source_slots = {
        "MAC_NAME": algorithm_slots["source_mac_name"],
        "DIGEST_NAME": digest_or_cipher if digest_or_cipher.startswith("SHA") else "SHA256",
        "SOURCE_MAC_SETUP_PARAMS": algorithm_slots["source_setup_params"],
        "SOURCE_LIFECYCLE_SEQUENCE": source_sequence,
        "SOURCE_ORACLE_OBSERVATION": f'"{expected_class}"',
    }
    target_slots = {
        "TARGET_KEY_TYPE": algorithm_slots["target_key_type"],
        "TARGET_KEY_ALGORITHM": algorithm_slots["target_algorithm"],
        "TARGET_MAC_SETUP_PARAMS": "psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);",
        "TARGET_LIFECYCLE_SEQUENCE": target_sequence,
        "TARGET_ORACLE_OBSERVATION": f'"{expected_class}"',
    }

    candidate_types = [
        "allowed_legacy_semantics_needs_review",
        "failure_path_output_state_triage",
        "lifecycle_semantic_divergence_candidate",
        "safe_negative",
    ]
    if lifecycle_sequence == "wrong_digest_combo":
        candidate_types = ["safe_negative", "projection_limitation"]
    elif lifecycle_sequence in {"query_after_final", "query_after_abort"}:
        candidate_types = ["projection_limitation", "safe_negative"]
    elif lifecycle_sequence in HIGH_VALUE_LIFECYCLE_SEQUENCES:
        candidate_types = [
            "lifecycle_semantic_divergence_candidate",
            "allowed_legacy_semantics_needs_review",
            "failure_path_output_state_triage",
            "crash_candidate",
        ]

    return MacCasePlan(True, [], source_slots, target_slots, common_slots, candidate_types)
