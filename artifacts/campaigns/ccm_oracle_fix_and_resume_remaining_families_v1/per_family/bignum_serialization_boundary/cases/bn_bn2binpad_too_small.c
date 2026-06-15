/*
 * Auto campaign BIGNUM serialization boundary harness.
 * Local serialization/length semantics only.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>

int main(void)
{
    const char *case_id = "bn_bn2binpad_too_small";
    const char *expected_behavior = "error_or_documented";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret = 0;
    int len = 0;
    unsigned char buf[128] = {0};
    unsigned char out[128] = {0};
    BIGNUM *a = BN_new();
    BIGNUM *b = NULL;
    char *str = NULL;

    if (a == NULL)
        goto done;

    BN_hex2bn(&a, "A1B2C3");
    len = BN_num_bytes(a);
    ret = BN_bn2binpad(a, buf, len - 1);
    actual_behavior = (ret >= 0) ? "success" : "error";
    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;

    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;

done:

    printf("ORACLE_EVENT family=bignum_serialization_boundary\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    OPENSSL_free(str);
    BN_free(a);
    BN_free(b);
    return 0;
}
