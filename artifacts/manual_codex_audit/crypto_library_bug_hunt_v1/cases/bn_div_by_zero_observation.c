/*
 * Manual local audit harness for bn_usub_semantic.
 * No parser replay, DER trailing garbage, full-consumption oracle, or exploit chain.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

int main(void)
{
    const char *case_id = "bn_div_by_zero_observation";
    const char *expected_behavior = "observation";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *q = BN_new();
    BN_CTX *bn_ctx = BN_CTX_new();
    int ret = 0;
    const char *actual_behavior = "error";

    if (a == NULL || b == NULL || r == NULL || q == NULL || bn_ctx == NULL) goto done;
    BN_set_word(a, 9); BN_zero(b);
    ret = BN_div(q, r, a, b, bn_ctx); actual_behavior = (ret == 1) ? "success" : "error";

done:
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else if (strcmp(expected_behavior, "error_or_documented") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family=bn_usub_semantic\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    BN_free(a);
    BN_free(b);
    BN_free(r);
    BN_free(q);
    BN_CTX_free(bn_ctx);
    return 0;
}
