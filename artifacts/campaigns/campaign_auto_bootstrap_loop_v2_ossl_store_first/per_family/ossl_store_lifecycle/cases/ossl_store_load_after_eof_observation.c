/*
 * Auto campaign OSSL_STORE lifecycle harness.
 * Local files only; no DER trailing-garbage or full-consumption oracle.
 */
#include <stdio.h>
#include <string.h>

#include <openssl/store.h>

int main(void)
{
    const char *case_id = "ossl_store_load_after_eof_observation";
    const char *expected_behavior = "observation";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    const char *uri = "file:/tmp/crypto_pattern_fuzz_ossl_store_empty.txt";

    
    ctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (ctx != NULL) {
        while (!OSSL_STORE_eof(ctx) && !OSSL_STORE_error(ctx)) {
            info = OSSL_STORE_load(ctx);
            OSSL_STORE_INFO_free(info);
            info = NULL;
        }
        info = OSSL_STORE_load(ctx);
        actual_behavior = (info == NULL) ? "error" : "success";
    } else {
        actual_behavior = "error";
    }


    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family=ossl_store_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    OSSL_STORE_INFO_free(info);
    if (ctx != NULL)
        OSSL_STORE_close(ctx);
    return 0;
}
