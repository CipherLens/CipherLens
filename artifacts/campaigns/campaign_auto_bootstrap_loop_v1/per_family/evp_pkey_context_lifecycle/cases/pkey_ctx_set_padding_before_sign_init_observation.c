/*
 * Manual local audit harness for evp_pkey_context_lifecycle.
 * No parser replay, DER trailing garbage, full-consumption oracle, or exploit chain.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

int main(void)
{
    const char *case_id = "pkey_ctx_set_padding_before_sign_init_observation";
    const char *expected_behavior = "observation";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;
    const char *actual_behavior = "error";

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); ret = (ctx != NULL) ? EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) : 0; actual_behavior = (ret > 0) ? "success" : "error";

done:
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else if (strcmp(expected_behavior, "error_or_documented") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family=evp_pkey_context_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}
