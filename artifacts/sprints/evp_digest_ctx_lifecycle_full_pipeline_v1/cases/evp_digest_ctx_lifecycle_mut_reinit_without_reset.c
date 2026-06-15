/*
 * Generated from lifecycle_render_plan_v1 for evp_digest_ctx_lifecycle.
 * This is an EVP_MD_CTX lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

static const unsigned char message[] = "fixed digest lifecycle message";

int main(void)
{
    const char *case_id = "evp_digest_ctx_lifecycle_mut_reinit_without_reset";
    const char *expected_behavior = "success";
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

    ret_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_final = EVP_DigestFinal_ex(ctx, digest_out, &digest_out_len);
    ret_second_init = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ret_second_update = EVP_DigestUpdate(ctx, message, message_len);
    ret_second_final = EVP_DigestFinal_ex(ctx, digest_out_2, &digest_out_len_2);
    actual_behavior = (ret_init == 1 && ret_update == 1 && ret_final == 1 &&
                       ret_second_init == 1 && ret_second_update == 1 && ret_second_final == 1) ? "success" : "error";

    state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:
    printf("ORACLE_EVENT family=evp_digest_ctx_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy=reinit_without_reset\n");
    printf("ORACLE_EVENT oracle_rule=unexpected_failure_on_valid_sequence\n");

    if (ctx != NULL)
        EVP_MD_CTX_reset(ctx);
    EVP_MD_CTX_free(ctx);
    return state_transition_mismatch ? 10 : 0;
}

/* case symbol marker: evp_digest_ctx_lifecycle_mut_reinit_without_reset */
