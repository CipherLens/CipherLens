#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"

/*
 * Minimal PoC for MBEDTLS-POC-0028 / PR #5350.
 *
 * Trigger:
 *   PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3)
 *
 * CCM only allows tag lengths:
 *   4, 6, 8, 10, 12, 14, 16
 *
 * Buggy behavior:
 *   psa_aead_decrypt_setup() accepts invalid tag length 3.
 *
 * Fixed behavior:
 *   psa_aead_decrypt_setup() rejects invalid tag length 3 with
 *   PSA_ERROR_INVALID_ARGUMENT.
 */

static psa_status_t import_aes_key(psa_key_id_t *key_id, psa_algorithm_t alg)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    const unsigned char key_bytes[16] = {
        0x41, 0x89, 0x35, 0x1B,
        0x5C, 0xAE, 0xA3, 0x75,
        0xA0, 0x29, 0x9E, 0x81,
        0xC6, 0x21, 0xBF, 0x43
    };

    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);

    status = psa_import_key(&attributes, key_bytes, sizeof(key_bytes), key_id);
    psa_reset_key_attributes(&attributes);

    return status;
}

int main(void)
{
    psa_status_t status;
    psa_key_id_t key_id = 0;
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;

    psa_algorithm_t alg =
        PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 3);

    setbuf(stdout, NULL);

    printf("calling psa_crypto_init...\n");
    status = psa_crypto_init();
    printf("psa_crypto_init status=%d\n", (int) status);
    if (status != PSA_SUCCESS) {
        return 2;
    }

    printf("importing AES key...\n");
    status = import_aes_key(&key_id, alg);
    printf("psa_import_key status=%d\n", (int) status);
    if (status != PSA_SUCCESS) {
        return 2;
    }

    printf("calling psa_aead_decrypt_setup with CCM invalid tag length 3...\n");
    status = psa_aead_decrypt_setup(&operation, key_id, alg);

    printf("setup status=%d\n", (int) status);
    printf("expected_buggy=%d\n", (int) PSA_SUCCESS);
    printf("expected_fixed=%d\n", (int) PSA_ERROR_INVALID_ARGUMENT);

    if (status == PSA_SUCCESS) {
        printf("[BUG] invalid AEAD tag length accepted during setup.\n");
    } else if (status == PSA_ERROR_INVALID_ARGUMENT) {
        printf("[OK] invalid AEAD tag length rejected during setup.\n");
    } else {
        printf("[INFO] unexpected setup status=%d\n", (int) status);
    }

    psa_aead_abort(&operation);
    psa_destroy_key(key_id);

    return 0;
}
