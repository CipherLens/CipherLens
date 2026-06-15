#include <psa/crypto.h>

#include <stdio.h>
#include <string.h>

#define APPLICATION_REJECT "APPLICATION_REJECT"
#define APPLICATION_ACCEPTED_POST_FINISH_DATA "APPLICATION_ACCEPTED_POST_FINISH_DATA"

static const unsigned char authorized_prefix[] = "authorized-prefix";
static const unsigned char post_finish_data[] = "post-finish-data";

static void print_hex_field(const char *name, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void run_case(const char *algorithm,
                     const unsigned char *key,
                     size_t key_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    unsigned char tag_prefix[64] = {0};
    unsigned char tag_after_post_finish[64] = {0};
    size_t tag_prefix_len = 0;
    size_t tag_after_post_finish_len = 0;
    psa_status_t import_status;
    psa_status_t setup_status = PSA_ERROR_BAD_STATE;
    psa_status_t update_prefix_status = PSA_ERROR_BAD_STATE;
    psa_status_t finish_status = PSA_ERROR_BAD_STATE;
    psa_status_t post_finish_update_status = PSA_ERROR_BAD_STATE;
    psa_status_t final_after_post_finish_status = PSA_ERROR_BAD_STATE;
    const char *application_decision = APPLICATION_REJECT;

    (void) algorithm;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);

    import_status = psa_import_key(&attributes, key, key_len, &key_id);
    if (import_status == PSA_SUCCESS) {
        setup_status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
    }
    if (setup_status == PSA_SUCCESS) {
        update_prefix_status = psa_mac_update(
            &operation,
            authorized_prefix,
            strlen((const char *) authorized_prefix));
    }
    if (update_prefix_status == PSA_SUCCESS) {
        finish_status = psa_mac_sign_finish(
            &operation,
            tag_prefix,
            sizeof(tag_prefix),
            &tag_prefix_len);
    }

    if (finish_status == PSA_SUCCESS) {
        post_finish_update_status = psa_mac_update(
            &operation,
            post_finish_data,
            strlen((const char *) post_finish_data));
    }
    if (post_finish_update_status == PSA_SUCCESS) {
        final_after_post_finish_status = psa_mac_sign_finish(
            &operation,
            tag_after_post_finish,
            sizeof(tag_after_post_finish),
            &tag_after_post_finish_len);
        if (final_after_post_finish_status == PSA_SUCCESS) {
            application_decision = APPLICATION_ACCEPTED_POST_FINISH_DATA;
        }
    }

    printf("library=mbedtls_psa\n");
    printf("algorithm=%s\n", algorithm);
    printf("setup_status=%d\n", (int) setup_status);
    printf("update_prefix_status=%d\n", (int) update_prefix_status);
    printf("finish_status=%d\n", (int) finish_status);
    print_hex_field("tag_prefix", tag_prefix, tag_prefix_len);
    printf("post_finish_update_status=%d\n", (int) post_finish_update_status);
    printf("final_after_post_finish_status=%d\n", (int) final_after_post_finish_status);
    print_hex_field("tag_after_post_finish", tag_after_post_finish, tag_after_post_finish_len);
    printf("application_decision=%s\n", application_decision);
    printf("--\n");

    psa_mac_abort(&operation);
    if (key_id != 0) {
        psa_destroy_key(key_id);
    }
    psa_reset_key_attributes(&attributes);
}

int main(void)
{
    static const unsigned char key128[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char key256[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_status_t init_status = psa_crypto_init();
    if (init_status != PSA_SUCCESS) {
        printf("library=mbedtls_psa\n");
        printf("psa_crypto_init=%d\n", (int) init_status);
        return 1;
    }

    run_case("AES-128-CBC", key128, sizeof(key128));
    run_case("AES-256-CBC", key256, sizeof(key256));
    return 0;
}
