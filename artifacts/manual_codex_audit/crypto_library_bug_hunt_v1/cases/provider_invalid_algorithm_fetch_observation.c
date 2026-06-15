/*
 * Manual local audit harness for provider_fetch_lifecycle.
 * No parser replay, DER trailing garbage, full-consumption oracle, or exploit chain.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(void)
{
    const char *case_id = "provider_invalid_algorithm_fetch_observation";
    const char *expected_behavior = "observation";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    EVP_MD *md = NULL;
    const char *actual_behavior = "error";

    md = EVP_MD_fetch(NULL, "NO_SUCH_DIGEST_FOR_AUDIT", NULL); actual_behavior = (md == NULL) ? "error" : "success";

done:
    if (strcmp(expected_behavior, "success") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") != 0;
    else if (strcmp(expected_behavior, "error_or_documented") == 0)
        state_transition_mismatch = strcmp(actual_behavior, "success") == 0;
    else
        state_transition_mismatch = 0;

    printf("ORACLE_EVENT family=provider_fetch_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);

    EVP_MD_free(md);
    return 0;
}
