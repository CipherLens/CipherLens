/*
 * Local triage harness for OpenSSL EVP AES-CCM plaintext length announcement.
 * No public target access, exploit chain, DER trailing-garbage oracle, or UAF.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static void step_event(const char *case_id, const char *step, int ret, int len)
{
    printf("STEP_EVENT case_id=%s step=%s ret=%d len=%d\n", case_id, step, ret, len);
}

static void oracle_event(const char *case_id, const char *expected,
                         const char *actual, int semantic_mismatch,
                         int state_transition_mismatch)
{
    printf("ORACLE_EVENT family=cipher_aead_lifecycle_ccm\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=0\n");
}

static int valid_encrypt(unsigned char *ciphertext, unsigned char *tag,
                         int use_aad, int announce_len, const char *case_id,
                         int emit_steps)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char aad[8] = {1,2,3,4,5,6,7,8};
    unsigned char plaintext[] = "local ccm msg";
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int final_len = 0;
    int r_new = ctx != NULL;
    int r_init1 = 0, r_ivlen = 0, r_taglen = 0, r_init2 = 0;
    int r_len = -1, r_aad = -1, r_payload = 0, r_final = 0, r_gettag = 0;
    int plaintext_len = (int)(sizeof(plaintext) - 1);

    if (emit_steps)
        step_event(case_id, "EVP_CIPHER_CTX_new", r_new, len);
    if (ctx == NULL)
        return 0;

    r_init1 = EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    if (emit_steps) step_event(case_id, "EncryptInit_cipher", r_init1, len);
    r_ivlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
    if (emit_steps) step_event(case_id, "CTRL_SET_IVLEN", r_ivlen, len);
    r_taglen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, NULL);
    if (emit_steps) step_event(case_id, "CTRL_SET_TAGLEN", r_taglen, len);
    r_init2 = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    if (emit_steps) step_event(case_id, "EncryptInit_key_iv", r_init2, len);
    if (announce_len) {
        r_len = EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);
        if (emit_steps) step_event(case_id, "EncryptUpdate_length_announcement", r_len, len);
    } else if (emit_steps) {
        step_event(case_id, "EncryptUpdate_length_announcement_skipped", -1, len);
    }
    if (use_aad) {
        r_aad = EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof(aad));
        if (emit_steps) step_event(case_id, "EncryptUpdate_aad", r_aad, len);
    } else if (emit_steps) {
        step_event(case_id, "EncryptUpdate_aad_skipped", -1, len);
    }
    r_payload = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (emit_steps) step_event(case_id, "EncryptUpdate_payload", r_payload, len);
    r_final = EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len);
    if (emit_steps) step_event(case_id, "EncryptFinal", r_final, final_len);
    r_gettag = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16, tag);
    if (emit_steps) step_event(case_id, "CTRL_GET_TAG", r_gettag, len);
    EVP_CIPHER_CTX_free(ctx);

    if (announce_len && use_aad)
        return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
            && r_len == 1 && r_aad == 1 && r_payload == 1 && r_final == 1 && r_gettag == 1;
    if (!announce_len && use_aad)
        return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
            && r_aad == 1 && r_payload == 1 && r_final == 1 && r_gettag == 1;
    return r_init1 == 1 && r_ivlen == 1 && r_taglen == 1 && r_init2 == 1
        && r_payload == 1 && r_final == 1 && r_gettag == 1;
}

static int decrypt_without_length(unsigned char *ciphertext, unsigned char *tag,
                                  const char *case_id)
{
    unsigned char key[16] = {0};
    unsigned char iv[12] = {0};
    unsigned char out[64] = {0};
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int r_new = ctx != NULL;
    int r_init1 = 0, r_ivlen = 0, r_settag = 0, r_init2 = 0, r_payload = 0, r_final = 0;
    int plaintext_len = (int)(sizeof("local ccm msg") - 1);

    step_event(case_id, "EVP_CIPHER_CTX_new", r_new, len);
    if (ctx == NULL)
        return 0;
    r_init1 = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL);
    step_event(case_id, "DecryptInit_cipher", r_init1, len);
    r_ivlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, sizeof(iv), NULL);
    step_event(case_id, "CTRL_SET_IVLEN", r_ivlen, len);
    r_settag = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 16, tag);
    step_event(case_id, "CTRL_SET_TAG", r_settag, len);
    r_init2 = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    step_event(case_id, "DecryptInit_key_iv", r_init2, len);
    step_event(case_id, "DecryptUpdate_length_announcement_skipped", -1, len);
    r_payload = EVP_DecryptUpdate(ctx, out, &len, ciphertext, plaintext_len);
    step_event(case_id, "DecryptUpdate_payload", r_payload, len);
    r_final = EVP_DecryptFinal_ex(ctx, out + len, &len);
    step_event(case_id, "DecryptFinal", r_final, len);
    EVP_CIPHER_CTX_free(ctx);
    return r_init1 == 1 && r_ivlen == 1 && r_settag == 1 && r_init2 == 1 && r_payload == 1;
}

int main(void)
{
    unsigned char ciphertext[64] = {0};
    unsigned char tag[16] = {0};
    unsigned char scratch_ct[64] = {0};
    unsigned char scratch_tag[16] = {0};
    int ok = 0;

    ok = valid_encrypt(ciphertext, tag, 1, 1, "valid_control_with_plaintext_length_announced", 1);
    oracle_event("valid_control_with_plaintext_length_announced", "success",
                 ok ? "success" : "error", ok ? 0 : 1, ok ? 0 : 1);

    ok = valid_encrypt(scratch_ct, scratch_tag, 1, 0,
                       "candidate_without_plaintext_length_announcement", 1);
    oracle_event("candidate_without_plaintext_length_announcement", "error_or_documented",
                 ok ? "success" : "error", 0, ok ? 1 : 0);

    ok = valid_encrypt(scratch_ct, scratch_tag, 0, 0,
                       "no_aad_without_plaintext_length_announcement", 1);
    oracle_event("no_aad_without_plaintext_length_announcement", "observation",
                 ok ? "success" : "error", 0, 0);

    ok = decrypt_without_length(ciphertext, tag,
                                "decrypt_side_without_length_announcement_if_applicable");
    oracle_event("decrypt_side_without_length_announcement_if_applicable", "observation",
                 ok ? "success" : "error", 0, 0);

    return 0;
}
