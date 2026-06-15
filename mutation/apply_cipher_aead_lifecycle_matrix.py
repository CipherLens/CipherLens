import argparse
from pathlib import Path
from typing import Any, Dict, List

import yaml


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def c_quote(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def indent(code: str, spaces: int = 4) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else "" for line in code.strip().splitlines())


def normal_encrypt_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0, total = 0;

printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
if (ret != 1) goto fail;
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
total += outlen;
ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
printf("STEP=Final ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
total += outlen;
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("STEP=GetTag ret=%d\n", ret);
if (ret != 1) goto fail;
print_hex("CIPHERTEXT", ciphertext, total);
print_hex("TAG", tag, 16);
printf("CASE_RESULT=ok\n");
EVP_CIPHER_CTX_free(ctx);
return 0;

fail:
printf("CASE_RESULT=harness_error\n");
EVP_CIPHER_CTX_free(ctx);
return 2;
'''


def normal_decrypt_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char plaintext[128] = {0};
unsigned char tag[16] = {0};
int ciphertext_len = 0;
int ret = 0, outlen = 0, total = 0;

if (!encrypt_reference(ciphertext, &ciphertext_len, tag, 16)) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
ret = EVP_DecryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=DecryptInit ret=%d\n", ret);
if (ret != 1) goto fail;
ret = EVP_DecryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
total += outlen;
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
printf("STEP=SetTag ret=%d\n", ret);
if (ret != 1) goto fail;
ret = EVP_DecryptFinal_ex(ctx, plaintext + total, &outlen);
printf("STEP=Final ret=%d outlen=%d\n", ret, outlen);
if (ret != 1) goto fail;
total += outlen;
printf("PLAINTEXT_MATCH=%d\n", total == (int) strlen((const char *) PLAINTEXT)
       && memcmp(plaintext, PLAINTEXT, (size_t) total) == 0);
printf("CASE_RESULT=ok\n");
EVP_CIPHER_CTX_free(ctx);
return 0;

fail:
printf("CASE_RESULT=harness_error\n");
EVP_CIPHER_CTX_free(ctx);
return 2;
'''


def repeated_final_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0, total = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
total += outlen;
ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
printf("STEP=Final ret=%d outlen=%d\n", ret, outlen);
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("STEP=GetTag ret=%d\n", ret);
ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
printf("MUTATION_STEP=EncryptFinal_second ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def update_after_final_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[160] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0, total = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
total += outlen;
ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
printf("STEP=Final ret=%d outlen=%d\n", ret, outlen);
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("STEP=GetTag ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, ciphertext + total, &outlen, EXTRA, (int) strlen((const char *) EXTRA));
printf("MUTATION_STEP=EncryptUpdate_after_final ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def final_without_update_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[64] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_EncryptFinal_ex(ctx, ciphertext, &outlen);
printf("MUTATION_STEP=Final_without_data_update ret=%d outlen=%d\n", ret, outlen);
int tag_ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("MUTATION_STEP=GetTag_after_empty_final ret=%d\n", tag_ret);
printf("CASE_RESULT=%s\n", (ret == 1 && tag_ret == 1) ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def get_tag_before_final_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("MUTATION_STEP=GetTag_before_final ret=%d\n", ret);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def set_tag_after_final_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char plaintext[128] = {0};
unsigned char tag[16] = {0};
int ciphertext_len = 0;
int ret = 0, outlen = 0;
if (!encrypt_reference(ciphertext, &ciphertext_len, tag, 16)) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_DecryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=DecryptInit ret=%d\n", ret);
ret = EVP_DecryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);
printf("MUTATION_STEP=Final_before_set_tag ret=%d outlen=%d\n", ret, outlen);
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
printf("MUTATION_STEP=SetTag_after_final ret=%d\n", ret);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def aad_after_data_update_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
int ret = 0, outlen = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update_first ret=%d outlen=%d\n", ret, outlen);
ret = EVP_EncryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("MUTATION_STEP=AAD_Update_after_data ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def decrypt_without_set_tag_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char plaintext[128] = {0};
unsigned char tag[16] = {0};
int ciphertext_len = 0;
int ret = 0, outlen = 0, total = 0;
if (!encrypt_reference(ciphertext, &ciphertext_len, tag, 16)) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_DecryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=DecryptInit ret=%d\n", ret);
ret = EVP_DecryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
total += outlen;
ret = EVP_DecryptFinal_ex(ctx, plaintext + total, &outlen);
printf("MUTATION_STEP=Final_without_set_tag ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def wrong_tag_length_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
unsigned char plaintext[128] = {0};
unsigned char tag[16] = {0};
int ciphertext_len = 0;
int ret = 0, outlen = 0, total = 0;
if (!encrypt_reference(ciphertext, &ciphertext_len, tag, 16)) {
    printf("CASE_RESULT=harness_error\n");
    return 2;
}
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_DecryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=DecryptInit ret=%d\n", ret);
ret = EVP_DecryptUpdate(ctx, NULL, &outlen, AAD, (int) strlen((const char *) AAD));
printf("STEP=AAD_Update ret=%d outlen=%d\n", ret, outlen);
ret = EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, ciphertext_len);
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
total += outlen;
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 8, tag);
printf("MUTATION_STEP=SetTag_wrong_length_8 ret=%d\n", ret);
ret = EVP_DecryptFinal_ex(ctx, plaintext + total, &outlen);
printf("MUTATION_STEP=Final_with_wrong_tag_length ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def ctx_reuse_after_final_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[256] = {0};
unsigned char tag[16] = {0};
int ret = 0, outlen = 0, total = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("STEP=Data_Update ret=%d outlen=%d\n", ret, outlen);
total += outlen;
ret = EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen);
printf("STEP=Final ret=%d outlen=%d\n", ret, outlen);
ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
printf("STEP=GetTag ret=%d\n", ret);
ret = EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);
printf("MUTATION_STEP=Reinit_null_after_final ret=%d\n", ret);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, EXTRA, (int) strlen((const char *) EXTRA));
printf("MUTATION_STEP=Update_after_reinit_null ret=%d outlen=%d\n", ret, outlen);
int final_ret = EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen);
printf("MUTATION_STEP=Final_after_reuse ret=%d outlen=%d\n", final_ret, outlen);
printf("CASE_RESULT=%s\n", (ret == 1 && final_ret == 1) ? "permissive_behavior" : "expected_reject");
EVP_CIPHER_CTX_free(ctx);
return 0;
'''


def cleanup_then_update_body() -> str:
    return r'''
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
unsigned char ciphertext[128] = {0};
int ret = 0, outlen = 0;
printf("STEP=EVP_CIPHER_CTX_new ret=%d\n", ctx != NULL);
if (ctx == NULL) { printf("CASE_RESULT=harness_error\n"); return 2; }
ret = EVP_EncryptInit_ex(ctx, select_cipher(), NULL, KEY, IV);
printf("STEP=EncryptInit ret=%d\n", ret);
EVP_CIPHER_CTX_free(ctx);
printf("STEP=EVP_CIPHER_CTX_free ret=1\n");
fflush(stdout);
ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, PLAINTEXT, (int) strlen((const char *) PLAINTEXT));
printf("MUTATION_STEP=EncryptUpdate_after_free ret=%d outlen=%d\n", ret, outlen);
printf("CASE_RESULT=%s\n", ret == 1 ? "permissive_behavior" : "expected_reject");
return 0;
'''


BODY_BY_NAME = {
    "normal_encrypt_control": normal_encrypt_body,
    "normal_decrypt_control": normal_decrypt_body,
    "repeated_final": repeated_final_body,
    "update_after_final": update_after_final_body,
    "final_without_update": final_without_update_body,
    "get_tag_before_final": get_tag_before_final_body,
    "set_tag_after_final": set_tag_after_final_body,
    "aad_after_data_update": aad_after_data_update_body,
    "decrypt_without_set_tag": decrypt_without_set_tag_body,
    "wrong_tag_length": wrong_tag_length_body,
    "ctx_reuse_after_final": ctx_reuse_after_final_body,
    "cleanup_then_update": cleanup_then_update_body,
}


def render_case(template: str, case: Dict[str, Any]) -> str:
    case_name = str(case["case_name"])
    body_factory = BODY_BY_NAME.get(case_name)
    if body_factory is None:
        raise ValueError(f"unsupported AEAD case_name: {case_name}")
    rendered = template
    replacements = {
        'AEAD_CASE_ID "unset_case_id"': f'AEAD_CASE_ID "{c_quote(case["case_id"])}"',
        'AEAD_CASE_NAME "unset_case_name"': f'AEAD_CASE_NAME "{c_quote(case_name)}"',
        'AEAD_ALGORITHM "aes-128-gcm"': f'AEAD_ALGORITHM "{c_quote(case["algorithm"])}"',
        'AEAD_MODE "encrypt"': f'AEAD_MODE "{c_quote(case["mode"])}"',
        'AEAD_STATE_SEQUENCE "unset_state_sequence"': f'AEAD_STATE_SEQUENCE "{c_quote(case["state_sequence"])}"',
    }
    for old, new in replacements.items():
        rendered = rendered.replace(old, new)
    return rendered.replace("AEAD_CASE_BODY", indent(body_factory(), 4))


def selected_cases(matrix: Dict[str, Any]) -> List[Dict[str, Any]]:
    cases = matrix.get("selected_cases")
    if not isinstance(cases, list):
        raise ValueError("selected_aead_cases.yaml must contain selected_cases list")
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Render OpenSSL EVP AEAD lifecycle mutation cases.")
    parser.add_argument("--template", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    template = Path(args.template).read_text(encoding="utf-8")
    matrix = load_yaml(Path(args.matrix))
    out_root = Path(args.out_root)
    cases = selected_cases(matrix)

    for case in cases:
        case_id = str(case["case_id"])
        bucket = "controls" if case.get("case_type") == "safety_control" else "mutations"
        out_dir = out_root / bucket / case_id
        out_c = out_dir / f"{case_id}_openssl.c"
        write_text(out_c, render_case(template, case))

        manifest = {
            "case_id": case_id,
            "family": matrix.get("family", "cipher_aead_lifecycle"),
            "execution_mode": "B_controlled_family_mutation",
            "target_library": "openssl",
            "case_name": case.get("case_name"),
            "algorithm": case.get("algorithm"),
            "mode": case.get("mode"),
            "state_sequence": case.get("state_sequence"),
            "case_type": case.get("case_type"),
            "expected_oracle": case.get("expected_oracle"),
            "rendered_source": str(out_c),
        }
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "case_manifest.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)

        template_meta = {
            "template_id": "CIPHER_AEAD_LIFECYCLE_MUTATION_V1",
            "harness_family": "cipher_aead_lifecycle",
            "oracle_type": "aead_lifecycle_semantic_or_crash_oracle",
            "target_library": "openssl",
            "target_api": "EVP_AEAD_GCM_lifecycle",
            "render_matrix_case": manifest,
        }
        with (out_dir / "template_meta.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(template_meta, f, allow_unicode=True, sort_keys=False)
        print(f"[OK] rendered {case_id} -> {out_c}")

    print("=" * 80)
    print(f"[SUMMARY] rendered cases: {len(cases)}")
    print(f"[SUMMARY] output root: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
