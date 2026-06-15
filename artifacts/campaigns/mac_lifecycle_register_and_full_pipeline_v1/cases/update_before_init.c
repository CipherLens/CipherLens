/*
 * Generated from lifecycle_render_plan_v1 for mac_lifecycle.
 * This is an EVP_MAC HMAC lifecycle harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

static const unsigned char key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char empty_key[] = { 0x00 };
static const unsigned char message[] = "fixed mac lifecycle message";

int main(void)
{
    const char *case_id = "update_before_init";
    const char *expected_behavior = "error_or_documented";
    const char *actual_behavior = "error";
    int state_transition_mismatch = 0;
    int crash_or_sanitizer = 0;
    int ret_init = 0;
    int ret_update = 0;
    int ret_final = 0;
    int ret_after = 0;
    int ret_second_init = 0;
    int ret_second_update = 0;
    int ret_second_final = 0;
    unsigned char mac_out[EVP_MAX_MD_SIZE];
    unsigned char mac_out_2[EVP_MAX_MD_SIZE];
    size_t mac_out_len = 0;
    size_t mac_out_len_2 = 0;
    size_t key_len = sizeof(key);
    size_t message_len = sizeof(message) - 1;
    char digest_name[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;

    memset(mac_out, 0, sizeof(mac_out));
    memset(mac_out_2, 0, sizeof(mac_out_2));
    if (mac == NULL)
        goto done;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto done;

    ret_update = EVP_MAC_update(ctx, message, message_len);
    actual_behavior = (ret_update == 1) ? "success" : "error";

    state_transition_mismatch = strcmp(actual_behavior, "success") == 0;

done:
    printf("ORACLE_EVENT family=mac_lifecycle\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT state_transition_mismatch=%d\n", state_transition_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy=update_before_init\n");
    printf("ORACLE_EVENT oracle_rule=unexpected_success_after_invalid_state\n");

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return state_transition_mismatch ? 10 : 0;
}

/* case symbol marker: update_before_init */
