/*
 * Generated from semantic_render_plan_v1 for pkey_verify_semantic.
 * This case is a semantic EVP sign/verify harness, not a parser replay.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static const unsigned char base_message[] = "fixed deterministic semantic seed message";

static EVP_PKEY *generate_rsa_key(void)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (kctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(kctx) <= 0)
        goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0)
        goto done;
    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

static int sign_message(EVP_PKEY *key, const unsigned char *msg, size_t msg_len,
                        unsigned char **sig, size_t *sig_len)
{
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0)
        goto done;
    if (EVP_DigestSignUpdate(ctx, msg, msg_len) <= 0)
        goto done;
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) <= 0)
        goto done;
    *sig = OPENSSL_malloc(*sig_len);
    if (*sig == NULL)
        goto done;
    if (EVP_DigestSignFinal(ctx, *sig, sig_len) <= 0)
        goto done;
    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int verify_message(EVP_PKEY *key, const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len)
{
    int ret = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return -1;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, key) <= 0)
        goto done;
    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) <= 0)
        goto done;
    ret = EVP_DigestVerifyFinal(ctx, sig, sig_len);

done:
    EVP_MD_CTX_free(ctx);
    return ret;
}

int main(void)
{
    const char *case_id = "pkey_verify_semantic_mut_signature_truncate";
    const char *expected_behavior = "reject";
    const char *actual_behavior = "error";
    int semantic_mismatch = 0;
    int crash_or_sanitizer = 0;
    int verify_ret = -1;
    int exit_code = 0;
    EVP_PKEY *signing_key = NULL;
    EVP_PKEY *verify_key = NULL;
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    unsigned char verify_sig[512];
    size_t verify_sig_len = 0;
    unsigned char verify_input[256];
    size_t verify_input_len = sizeof(base_message) - 1;

    memcpy(verify_input, base_message, verify_input_len);

    signing_key = generate_rsa_key();
    if (signing_key == NULL)
        goto done;
    verify_key = signing_key;

    if (!sign_message(signing_key, base_message, sizeof(base_message) - 1, &signature, &signature_len))
        goto done;
    if (signature_len > sizeof(verify_sig))
        goto done;
    memcpy(verify_sig, signature, signature_len);
    verify_sig_len = signature_len;

    if (verify_sig_len > 0)
        verify_sig_len -= 1;

    verify_ret = verify_message(verify_key, verify_input, verify_input_len, verify_sig, verify_sig_len);
    if (verify_ret == 1)
        actual_behavior = "accept";
    else if (verify_ret == 0)
        actual_behavior = "reject";
    else
        actual_behavior = "error";

    if (strcmp(expected_behavior, "accept") == 0) {
        semantic_mismatch = strcmp(actual_behavior, "accept") != 0;
    } else if (strcmp(expected_behavior, "reject") == 0) {
        semantic_mismatch = strcmp(actual_behavior, "accept") == 0;
    } else {
        semantic_mismatch = 1;
    }
    exit_code = semantic_mismatch ? 10 : 0;

done:
    if (signing_key == NULL || verify_key == NULL || signature == NULL) {
        actual_behavior = "error";
        semantic_mismatch = strcmp(expected_behavior, "accept") == 0 ? 1 : 0;
        exit_code = semantic_mismatch ? 10 : 0;
    }
    printf("ORACLE_EVENT family=pkey_verify_semantic\n");
    printf("ORACLE_EVENT case_id=%s\n", case_id);
    printf("ORACLE_EVENT expected_behavior=%s\n", expected_behavior);
    printf("ORACLE_EVENT actual_behavior=%s\n", actual_behavior);
    printf("ORACLE_EVENT semantic_mismatch=%d\n", semantic_mismatch);
    printf("ORACLE_EVENT crash_or_sanitizer=%d\n", crash_or_sanitizer);
    printf("ORACLE_EVENT mutation_strategy=signature_corruption_truncate\n");

    OPENSSL_free(signature);
    verify_key = NULL;

    EVP_PKEY_free(verify_key);
    EVP_PKEY_free(signing_key);
    return exit_code;
}

/* case symbol marker: pkey_verify_semantic_mut_signature_truncate */
