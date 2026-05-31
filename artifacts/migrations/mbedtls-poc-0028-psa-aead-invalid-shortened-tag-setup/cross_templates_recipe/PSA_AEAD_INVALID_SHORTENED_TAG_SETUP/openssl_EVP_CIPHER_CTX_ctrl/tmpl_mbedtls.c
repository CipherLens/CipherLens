#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"

#define TAG_LENGTH [TAG_LENGTH]
#define KEY_BITS   [KEY_BITS]

/* PSA_KEY_TYPE_AES */
#define KEY_TYPE_VALUE [KEY_TYPE]

/*
 * CCM allows only even tag lengths from 4 to 16.
 * Returns 1 if valid, 0 if invalid.
 */
static int is_valid_ccm_tag_length(int tlen)
{
    return (tlen >= 4 && tlen <= 16 && (tlen % 2 == 0));
}

static psa_status_t import_aes_key(psa_key_id_t *key_id, psa_algorithm_t alg,
                                   psa_key_type_t ktype, size_t kbits)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    const unsigned char key_bytes[32] = {
        0x41, 0x89, 0x35, 0x1B, 0x5C, 0xAE, 0xA3, 0x75,
        0xA0, 0x29, 0x9E, 0x81, 0xC6, 0x21, 0xBF, 0x43,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    psa_status_t st;

    psa_set_key_type(&attr, ktype);
    psa_set_key_bits(&attr, (unsigned int) kbits);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, alg);

    st = psa_import_key(&attr, key_bytes, kbits / 8, key_id);
    psa_reset_key_attributes(&attr);
    return st;
}

int main(void)
{
    psa_status_t status;
    psa_key_id_t key_id = 0;
    psa_aead_operation_t operation = PSA_AEAD_OPERATION_INIT;
    psa_algorithm_t alg;
    int key_imported = 0;

    setbuf(stdout, NULL);

    printf("template_mutation TAG_LENGTH=%d\n", TAG_LENGTH);
    printf("template_mutation KEY_BITS=%d\n", KEY_BITS);

    /*
     * Historical bug (PR #5350):
     *   psa_aead_setup() did not validate shortened CCM tag length.
     *   CCM tag length 3 was accepted (PSA_SUCCESS) in the buggy version.
     *   Fixed: PSA_ERROR_INVALID_ARGUMENT returned for invalid tag lengths.
     */
    alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, TAG_LENGTH);

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("[ERROR] psa_crypto_init failed: %d\n", (int) status);
        return 2;
    }

    status = import_aes_key(&key_id, alg, (psa_key_type_t) KEY_TYPE_VALUE, KEY_BITS);
    printf("psa_import_key status=%d\n", (int) status);
    if (status != PSA_SUCCESS) {
        printf("[INFO] psa_import_key rejected alg (tag_len=%d). status=%d\n",
               TAG_LENGTH, (int) status);
        goto cleanup;
    }
    key_imported = 1;

    printf("calling psa_aead_decrypt_setup (TAG_LENGTH=%d)...\n", TAG_LENGTH);
    status = psa_aead_decrypt_setup(&operation, key_id, alg);
    printf("setup_status=%d\n", (int) status);

    if (!is_valid_ccm_tag_length(TAG_LENGTH)) {
        if (status == PSA_SUCCESS) {
            printf("[BUG] source accepted invalid CCM shortened tag length=%d\n", TAG_LENGTH);
        } else {
            printf("[OK] source rejected invalid CCM shortened tag length=%d. status=%d\n",
                   TAG_LENGTH, (int) status);
        }
    } else {
        if (status == PSA_SUCCESS) {
            printf("[OK] source accepted valid CCM tag length=%d.\n", TAG_LENGTH);
        } else {
            printf("[INFO] source rejected valid CCM tag length=%d. status=%d (needs triage)\n",
                   TAG_LENGTH, (int) status);
        }
    }

cleanup:
    psa_aead_abort(&operation);
    if (key_imported) {
        psa_destroy_key(key_id);
    }
    return 0;
}
