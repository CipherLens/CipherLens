/*
 * Generated from lifecycle_render_plan_v1 for evp_cipher_ctx_lifecycle.
 * This is an EVP_CIPHER_CTX lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static const unsigned char plaintext[] = "fixed cipher lifecycle message block";
static const unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char iv[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

int main(void)
{
    const char *case_id = "evp_cipher_ctx_lifecycle_mut_update_before_init";
    const char *expected_behavior = "error_or_documented";
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

    ret_update = EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len);
    actual_behavior = (ret_update == 1) ? "success" : "error";

    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;

done:
    printf("ORACLE_EVENT family=evp_cipher_ctx_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy=update_before_init\n");
    printf("ORACLE_EVENT oracle_rule=unexpected_success_after_invalid_state\n");

    if (ctx != NULL)
        EVP_CIPHER_CTX_reset(ctx);
    EVP_CIPHER_CTX_free(ctx);
    return state_transition_mismatch ? 10 : 0;
}

/* case symbol marker: evp_cipher_ctx_lifecycle_mut_update_before_init */
