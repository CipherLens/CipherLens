#include <psa/crypto.h>

#include <stdio.h>
#include <string.h>

static void run_case(const char *algorithm, const char *sequence,
                     const unsigned char *key, size_t key_len)
{
    static const unsigned char message[] = {
        0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
        0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
        0x67
    };
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    psa_key_id_t key_id = 0;
    psa_status_t import_status;
    psa_status_t setup_status = PSA_ERROR_BAD_STATE;
    psa_status_t update1_status = PSA_ERROR_BAD_STATE;
    psa_status_t finish1_status = PSA_ERROR_BAD_STATE;
    psa_status_t finish2_status = PSA_ERROR_BAD_STATE;
    psa_status_t finish3_status = PSA_ERROR_BAD_STATE;
    psa_status_t update_after_finish_status = PSA_ERROR_BAD_STATE;
    psa_status_t update_after_second_finish_status = PSA_ERROR_BAD_STATE;
    unsigned char mac1[64] = {0};
    unsigned char mac2[64] = {0};
    unsigned char mac3[64] = {0};
    size_t mac_len1 = 0;
    size_t mac_len2 = 0;
    size_t mac_len3 = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    import_status = psa_import_key(&attributes, key, key_len, &key_id);

    if (import_status == PSA_SUCCESS) {
        setup_status = psa_mac_sign_setup(&operation, key_id, PSA_ALG_CMAC);
        if (setup_status == PSA_SUCCESS) {
            update1_status = psa_mac_update(&operation, message, sizeof(message));
        }
        if (update1_status == PSA_SUCCESS) {
            finish1_status = psa_mac_sign_finish(&operation, mac1, sizeof(mac1), &mac_len1);
        }
        if (strcmp(sequence, "update_after_final") == 0) {
            if (finish1_status == PSA_SUCCESS) {
                update_after_finish_status = psa_mac_update(&operation, message, sizeof(message));
            }
        } else if (strcmp(sequence, "third_final") == 0) {
            if (finish1_status == PSA_SUCCESS) {
                finish2_status = psa_mac_sign_finish(&operation, mac2, sizeof(mac2), &mac_len2);
                finish3_status = psa_mac_sign_finish(&operation, mac3, sizeof(mac3), &mac_len3);
            }
        } else if (strcmp(sequence, "update_after_second_final") == 0) {
            if (finish1_status == PSA_SUCCESS) {
                finish2_status = psa_mac_sign_finish(&operation, mac2, sizeof(mac2), &mac_len2);
                update_after_second_finish_status =
                    psa_mac_update(&operation, message, sizeof(message));
                finish3_status = psa_mac_sign_finish(&operation, mac3, sizeof(mac3), &mac_len3);
            }
        }
    }

    printf("algorithm=%s\n", algorithm);
    printf("sequence=%s\n", sequence);
    printf("setup_status=%d\n", (int) setup_status);
    printf("update1_status=%d\n", (int) update1_status);
    printf("finish1_status=%d\n", (int) finish1_status);
    printf("finish2_status=%d\n", (int) finish2_status);
    printf("finish3_status=%d\n", (int) finish3_status);
    printf("update_after_finish_status=%d\n", (int) update_after_finish_status);
    printf("update_after_second_finish_status=%d\n", (int) update_after_second_finish_status);
    printf("mac_len1=%zu\n", mac_len1);
    printf("mac_len2=%zu\n", mac_len2);
    printf("mac_len3=%zu\n", mac_len3);
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
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("psa_crypto_init=%d\n", (int) status);
        return 1;
    }

    run_case("AES-128-CBC", "update_after_final", key128, sizeof(key128));
    run_case("AES-128-CBC", "third_final", key128, sizeof(key128));
    run_case("AES-128-CBC", "update_after_second_final", key128, sizeof(key128));
    run_case("AES-256-CBC", "update_after_final", key256, sizeof(key256));
    run_case("AES-256-CBC", "third_final", key256, sizeof(key256));
    run_case("AES-256-CBC", "update_after_second_final", key256, sizeof(key256));
    return 0;
}
