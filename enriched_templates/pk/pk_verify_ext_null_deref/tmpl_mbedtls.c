#include <stdio.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "psa/crypto.h"

#define KEY_BITS [KEY_BITS]
#define HASH_LEN [HASH_LEN]
#define SIG_LEN [SIG_LEN]
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
    unsigned char sig[SIG_LEN];

    const char *pers = "poc_pk_verify_ext_v2";

    mbedtls_pk_rsassa_pss_options pss_opts;
    pss_opts.mgf1_hash_id = [MD_ALG];
    pss_opts.expected_salt_len = [EXPECTED_SALT_LEN];

    setbuf(stdout, NULL);

    memset(hash, 0x2a, sizeof(hash));
    memset(sig, 0x5a, sizeof(sig));

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
     * Step 1: create a legacy RSA key.
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
     * Align with the official regression-test scenario:
     * RSASSA-PSS key path.
     */
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),
                            MBEDTLS_RSA_PKCS_V21,
                            MBEDTLS_MD_NONE);

    /*
     * Step 2: import into PSA and turn the PK context into an opaque context.
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
    printf("calling mbedtls_pk_verify_ext...\n");

    /*
     * Trigger point:
     *
     * Buggy version:
     *   no ctx type check before RSA-PSS path;
     *   mbedtls_pk_rsa(*ctx) may return NULL;
     *   NULL dereference occurs.
     *
     * Fixed version:
     *   returns MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE.
     */
    ret = mbedtls_pk_verify_ext([PK_VERIFY_TYPE],
                                &pss_opts,
                                &pk,
                                [MD_ALG],
                                hash,
                                sizeof(hash),
                                sig,
                                sizeof(sig));

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
