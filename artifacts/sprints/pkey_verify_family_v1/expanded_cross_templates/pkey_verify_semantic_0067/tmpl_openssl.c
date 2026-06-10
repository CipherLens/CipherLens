#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_BITS [KEY_BITS]
#define PADDING_MODE_VALUE [PADDING_MODE]
#define DIGEST_ALG_VALUE [DIGEST_ALG]
#define HASH_LEN_VALUE [HASH_LEN]
#define SIGNATURE_LEN_VALUE [SIGNATURE_LEN]

static const char *VERIFY_API_NAME = "[VERIFY_API]";
static const char *KEY_TYPE_NAME = "[KEY_TYPE]";
static const char *SIGNATURE_MUTATION = "[SIGNATURE_MUTATION]";
static const char *DIGEST_MUTATION = "[DIGEST_MUTATION]";
static const char *KEY_MUTATION = "[KEY_MUTATION]";
static const char *PADDING_MUTATION = "[PADDING_MUTATION]";
static const char *EXPECTED_VERDICT_CLASS = "[EXPECTED_VERDICT_CLASS]";

static const unsigned char baseline_message[] = "pkey verify semantic baseline message";
static unsigned char configured_hash[64] = [HASH_BYTES];
static unsigned char seed_signature[] = [SIGNATURE_BYTES];

static unsigned char signature_storage[512];
static unsigned char *signature = signature_storage;
static size_t signature_len = 0;

static EVP_PKEY *sign_key = NULL;
static EVP_PKEY *wrong_key = NULL;
static EVP_PKEY *verify_key = NULL;
static int verify_ret = -999;
static int exit_code = 5;

static int is_pss_padding(void)
{
    return PADDING_MODE_VALUE == RSA_PKCS1_PSS_PADDING;
}

static int verify_saltlen(void)
{
    if (strcmp(PADDING_MUTATION, "pss_saltlen_mismatch") == 0) {
        return 0;
    }
    return 32;
}

static size_t verify_message_len(void)
{
    if (strcmp(DIGEST_MUTATION, "wrong_hash_length") == 0) {
        return sizeof(baseline_message) > 8 ? 8 : sizeof(baseline_message);
    }
    return sizeof(baseline_message) - 1;
}

static size_t verify_hash_len(void)
{
    if (strcmp(DIGEST_MUTATION, "wrong_hash_length") == 0) {
        return HASH_LEN_VALUE;
    }
    return 32;
}

static int configure_pkey_ctx(EVP_PKEY_CTX *ctx, int for_sign)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, PADDING_MODE_VALUE) <= 0) {
        return 0;
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, for_sign ? EVP_sha256() : DIGEST_ALG_VALUE) <= 0) {
        return 0;
    }
    if (is_pss_padding()) {
        int saltlen = for_sign ? 32 : verify_saltlen();
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen) <= 0) {
            return 0;
        }
    }
    return 1;
}

static int make_rsa_key(int bits, EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        goto done;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        goto done;
    }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        goto done;
    }
    *out = key;
    key = NULL;
    ok = 1;

done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int make_digest_signature(EVP_PKEY *key, unsigned char **out, size_t *out_len)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t needed = 0;
    int ok = 0;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        goto done;
    }
    if (EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, key) <= 0) {
        goto done;
    }
    if (!configure_pkey_ctx(pctx, 1)) {
        goto done;
    }
    if (EVP_DigestSign(mdctx, NULL, &needed, baseline_message, sizeof(baseline_message) - 1) <= 0) {
        goto done;
    }
    if (needed > sizeof(signature_storage)) {
        goto done;
    }
    if (EVP_DigestSign(mdctx, signature_storage, &needed, baseline_message, sizeof(baseline_message) - 1) <= 0) {
        goto done;
    }
    *out = signature_storage;
    *out_len = needed;
    ok = 1;

done:
    EVP_MD_CTX_free(mdctx);
    return ok;
}

static int make_pkey_signature(EVP_PKEY *key, unsigned char **out, size_t *out_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t needed = 0;
    int ok = 0;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL) {
        goto done;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto done;
    }
    if (!configure_pkey_ctx(ctx, 1)) {
        goto done;
    }
    if (EVP_PKEY_sign(ctx, NULL, &needed, configured_hash, 32) <= 0) {
        goto done;
    }
    if (needed > sizeof(signature_storage)) {
        goto done;
    }
    if (EVP_PKEY_sign(ctx, signature_storage, &needed, configured_hash, 32) <= 0) {
        goto done;
    }
    *out = signature_storage;
    *out_len = needed;
    ok = 1;

done:
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void apply_signature_mutation(unsigned char *sig, size_t *sig_len, size_t cap)
{
    if (strcmp(SIGNATURE_MUTATION, "valid_signature") == 0) {
        return;
    }
    if (strcmp(SIGNATURE_MUTATION, "truncated_signature") == 0) {
        if (*sig_len > 8) {
            *sig_len -= 8;
        }
        return;
    }
    if (strcmp(SIGNATURE_MUTATION, "all_zero_signature") == 0) {
        memset(sig, 0, *sig_len);
        return;
    }
    if (strcmp(SIGNATURE_MUTATION, "bitflip_signature") == 0 ||
        strcmp(SIGNATURE_MUTATION, "invalid_signature") == 0) {
        if (*sig_len > 0 && cap > 0) {
            sig[0] ^= 0x80;
        }
        return;
    }
}

static int run_digest_verify(EVP_PKEY *key, unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int ret = -100;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return -101;
    }
    if (EVP_DigestVerifyInit(mdctx, &pctx, DIGEST_ALG_VALUE, NULL, key) <= 0) {
        ret = -102;
        goto done;
    }
    if (!configure_pkey_ctx(pctx, 0)) {
        ret = -103;
        goto done;
    }
    ret = EVP_DigestVerify(mdctx, sig, sig_len, baseline_message, verify_message_len());

done:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

static int run_pkey_verify(EVP_PKEY *key, unsigned char *sig, size_t sig_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -200;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (ctx == NULL) {
        return -201;
    }
    if (EVP_PKEY_verify_init(ctx) <= 0) {
        ret = -202;
        goto done;
    }
    if (!configure_pkey_ctx(ctx, 0)) {
        ret = -203;
        goto done;
    }
    ret = EVP_PKEY_verify(ctx, sig, sig_len, configured_hash, verify_hash_len());

done:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int main(void)
{
    (void)KEY_TYPE_NAME;
    (void)seed_signature;
    (void)SIGNATURE_LEN_VALUE;
    (void)HASH_LEN_VALUE;

    printf("[INFO] PKEY verify controlled case api=%s key_type=%s signature_mutation=%s digest_mutation=%s key_mutation=%s padding_mutation=%s\\n",
           VERIFY_API_NAME, KEY_TYPE_NAME, SIGNATURE_MUTATION, DIGEST_MUTATION,
           KEY_MUTATION, PADDING_MUTATION);

    [VERIFY_SETUP]

    [VERIFY_CALL]

    [VERIFY_ORACLE_OBSERVATION]

cleanup:
    if (exit_code != 0 && verify_ret < 0) {
        ERR_print_errors_fp(stdout);
    }
    EVP_PKEY_free(sign_key);
    EVP_PKEY_free(wrong_key);
    return exit_code;
}
