#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#define RSA_KEY_BITS [KEY_BITS]

int main(void)
{
    EVP_PKEY_CTX *kgen_ctx = NULL;
    EVP_PKEY *sign_key = NULL;
    EVP_PKEY *target_key = NULL;
    EVP_MD_CTX *sign_ctx = NULL;
    EVP_MD_CTX *verify_ctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char sig[512];
    size_t sig_len = sizeof(sig);
    const unsigned char test_data[] = "null_deref_dispatch_probe";
    size_t test_data_len = sizeof(test_data) - 1;
    int ret = 0;
    int exit_code = 0;

    setbuf(stdout, NULL);

    printf("template_mutation KEY_BITS=%d\n", RSA_KEY_BITS);

    /* Step 1: Generate RSA signing key */
    kgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kgen_ctx == NULL) {
        printf("[ERROR] RSA keygen ctx new failed.\n");
        return 2;
    }
    if (EVP_PKEY_keygen_init(kgen_ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(kgen_ctx, RSA_KEY_BITS) <= 0 ||
        EVP_PKEY_keygen(kgen_ctx, &sign_key) <= 0) {
        printf("[ERROR] RSA keygen failed.\n");
        EVP_PKEY_CTX_free(kgen_ctx);
        return 2;
    }
    EVP_PKEY_CTX_free(kgen_ctx);
    kgen_ctx = NULL;

    /* Step 2: Sign test data with RSA-PSS to produce a real signature */
    sign_ctx = EVP_MD_CTX_new();
    if (sign_ctx == NULL) {
        printf("[ERROR] sign ctx new failed.\n");
        goto cleanup;
    }
    if (EVP_DigestSignInit(sign_ctx, &pctx, EVP_sha256(), NULL, sign_key) <= 0) {
        printf("[ERROR] DigestSignInit failed.\n");
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) {
        printf("[ERROR] set RSA-PSS padding on sign ctx failed.\n");
        goto cleanup;
    }
    pctx = NULL;
    if (EVP_DigestSignUpdate(sign_ctx, test_data, test_data_len) <= 0 ||
        EVP_DigestSignFinal(sign_ctx, sig, &sig_len) <= 0) {
        printf("[ERROR] DigestSign failed.\n");
        goto cleanup;
    }
    EVP_MD_CTX_free(sign_ctx);
    sign_ctx = NULL;

    printf("rsa_sign_ok=yes sig_len=%zu\n", sig_len);

    /* Step 3: Generate incompatible EC key (NID_X9_62_prime256v1) */
    kgen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (kgen_ctx == NULL ||
        EVP_PKEY_keygen_init(kgen_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kgen_ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kgen_ctx, &target_key) <= 0) {
        printf("[ERROR] EC keygen failed.\n");
        goto cleanup;
    }
    EVP_PKEY_CTX_free(kgen_ctx);
    kgen_ctx = NULL;

    printf("ec_key_type=%d\n", EVP_PKEY_id(target_key));
    printf("calling EVP_DigestVerifyInit with incompatible EC key...\n");

    /* Step 4: Trigger - EVP_DigestVerifyInit with incompatible EC key */
    verify_ctx = EVP_MD_CTX_new();
    if (verify_ctx == NULL) {
        printf("[ERROR] verify ctx new failed.\n");
        goto cleanup;
    }

    ret = EVP_DigestVerifyInit(verify_ctx, &pctx, EVP_sha256(), NULL, target_key);
    printf("EVP_DigestVerifyInit ret=%d\n", ret);
    if (ret <= 0) {
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyInit.\n");
        exit_code = 0;
        goto cleanup;
    }

    /* Step 5: Probe RSA-PSS padding dispatch path */
    ret = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
    printf("EVP_PKEY_CTX_set_rsa_padding ret=%d\n", ret);
    if (ret <= 0) {
        printf("[OK] null_deref_dispatch: RSA-PSS padding rejected safely for incompatible EC key.\n");
        exit_code = 0;
        goto cleanup;
    }
    pctx = NULL;

    /* Step 6: Attempt verify update and final with incompatible key */
    ret = EVP_DigestVerifyUpdate(verify_ctx, test_data, test_data_len);
    printf("EVP_DigestVerifyUpdate ret=%d\n", ret);
    if (ret <= 0) {
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyUpdate.\n");
        exit_code = 0;
        goto cleanup;
    }

    ret = EVP_DigestVerifyFinal(verify_ctx, sig, sig_len);
    printf("EVP_DigestVerifyFinal ret=%d\n", ret);
    if (ret <= 0) {
        printf("[OK] null_deref_dispatch: incompatible EC key rejected safely at EVP_DigestVerifyFinal.\n");
        exit_code = 0;
    } else {
        printf("[TRIAGE] null_deref_dispatch: incompatible EC key verify unexpectedly succeeded. ret=%d\n", ret);
        exit_code = 2;
    }

cleanup:
    EVP_MD_CTX_free(sign_ctx);
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(sign_key);
    EVP_PKEY_free(target_key);
    EVP_PKEY_CTX_free(kgen_ctx);
    return exit_code;
}
