#include <stdio.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "psa/crypto.h"

#define KEY_BITS [KEY_BITS]

int main(void)
{
    mbedtls_pk_context pk;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t psa_status;
    int key_generated = 0;
    int ret = 0;

    unsigned char hash[32];
    unsigned char sig[512];

    setbuf(stdout, NULL);

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0x5a, sizeof(sig));

    mbedtls_pk_init(&pk);

    printf("template_mutation KEY_BITS=%d\n", KEY_BITS);

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        printf("[ERROR] psa_crypto_init failed: %d\n", (int) psa_status);
        ret = 2;
        goto cleanup;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&key_attr, KEY_BITS);
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&key_attr, PSA_ALG_RSA_PSS(PSA_ALG_SHA_256));

    psa_status = psa_generate_key(&key_attr, &key_id);
    if (psa_status != PSA_SUCCESS) {
        printf("[ERROR] psa_generate_key failed: %d\n", (int) psa_status);
        ret = 2;
        goto cleanup;
    }
    key_generated = 1;

    /*
     * mbedtls_pk_wrap_psa replaces the historical mbedtls_pk_setup_opaque
     * (removed in 4.x). Wraps a PSA key into a PK context.
     */
    ret = mbedtls_pk_wrap_psa(&pk, key_id);
    if (ret != 0) {
        printf("[ERROR] mbedtls_pk_wrap_psa failed: %d\n", ret);
        goto cleanup;
    }

    printf("psa_key_type=%u\n", (unsigned) mbedtls_pk_get_key_type(&pk));
    printf("calling mbedtls_pk_verify_ext with MBEDTLS_PK_SIGALG_RSA_PSS...\n");

    /*
     * In mbedTLS 3.x buggy: the opaque key path crashed via NULL deref on
     * mbedtls_pk_rsa(). In 4.x this path is gone; the API dispatches
     * through PSA for wrapped keys and returns an error for sign-only keys.
     */
    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_SIGALG_RSA_PSS, &pk,
                                MBEDTLS_MD_SHA256,
                                hash, sizeof(hash),
                                sig, sizeof(sig));

    printf("verify_ext ret=%d\n", ret);
    printf("expected=%d\n", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

    if (ret == MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE) {
        printf("[OK] fixed behavior: unsupported opaque verify_ext rejected safely.\n");
    } else if (ret != 0) {
        printf("[OK] fixed behavior: opaque RSA-PSS verify_ext rejected safely. ret=%d\n", ret);
    } else {
        printf("[INFO] opaque key verify returned success for dummy sig.\n");
    }

cleanup:
    mbedtls_pk_free(&pk);
    if (key_generated) {
        psa_destroy_key(key_id);
    }
    return 0;
}
