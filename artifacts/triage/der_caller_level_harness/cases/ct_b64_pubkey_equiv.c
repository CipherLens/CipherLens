#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    const unsigned char *bytes;
    size_t len;
    int append_second_der;
} suffix_case;

static const unsigned char suffix_00[] = {0x00};
static const unsigned char suffix_ff[] = {0xff};
static const unsigned char suffix_null_der[] = {0x05, 0x00};
static const unsigned char suffix_integer_zero[] = {0x02, 0x01, 0x00};
static const unsigned char suffix_empty_sequence[] = {0x30, 0x00};
static const unsigned char suffix_random_8[] = {
    0x83, 0x41, 0xa9, 0x7c, 0x02, 0xee, 0x10, 0x55
};

static const suffix_case SUFFIXES[] = {
    {"baseline_empty", NULL, 0, 0},
    {"trailing_00", suffix_00, sizeof(suffix_00), 0},
    {"trailing_ff", suffix_ff, sizeof(suffix_ff), 0},
    {"trailing_null_der", suffix_null_der, sizeof(suffix_null_der), 0},
    {"trailing_integer_zero", suffix_integer_zero, sizeof(suffix_integer_zero), 0},
    {"trailing_empty_sequence", suffix_empty_sequence, sizeof(suffix_empty_sequence), 0},
    {"trailing_random_8", suffix_random_8, sizeof(suffix_random_8), 0},
    {"second_der_object", NULL, 0, 1},
};

static EVP_PKEY *make_rsa_key(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto out;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        goto out;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int make_pubkey_der(unsigned char **der, int *der_len)
{
    EVP_PKEY *pkey = make_rsa_key();

    if (pkey == NULL)
        return 0;
    *der_len = i2d_PUBKEY(pkey, der);
    EVP_PKEY_free(pkey);
    return *der_len > 0;
}

static int b64_roundtrip(const unsigned char *in, size_t in_len,
                         unsigned char **decoded, int *decoded_len)
{
    int enc_len = 4 * (int)((in_len + 2) / 3);
    unsigned char *encoded = NULL;
    unsigned char *out = NULL;
    int out_len;
    int pad = 0;

    encoded = OPENSSL_malloc((size_t)enc_len + 1);
    out = OPENSSL_malloc((size_t)enc_len + 1);
    if (encoded == NULL || out == NULL)
        goto err;

    EVP_EncodeBlock(encoded, in, (int)in_len);
    if (enc_len >= 1 && encoded[enc_len - 1] == '=')
        pad++;
    if (enc_len >= 2 && encoded[enc_len - 2] == '=')
        pad++;
    out_len = EVP_DecodeBlock(out, encoded, enc_len);
    if (out_len < 0)
        goto err;
    out_len -= pad;
    if (out_len < 0)
        goto err;

    OPENSSL_free(encoded);
    *decoded = out;
    *decoded_len = out_len;
    return 1;

err:
    OPENSSL_free(encoded);
    OPENSSL_free(out);
    return 0;
}

static void run_case(const unsigned char *base_der, int base_len,
                     const suffix_case *suffix)
{
    size_t second_len = suffix->append_second_der ? (size_t)base_len : 0;
    size_t total_len = (size_t)base_len + suffix->len + second_len;
    size_t trailing_len = suffix->len + second_len;
    unsigned char *mutated = NULL;
    unsigned char *decoded = NULL;
    int decoded_len = 0;
    const unsigned char *p = NULL;
    EVP_PKEY *pkey = NULL;
    long consumed_len = 0;
    int baseline = suffix->len == 0 && !suffix->append_second_der;

    mutated = OPENSSL_malloc(total_len);
    if (mutated == NULL)
        goto harness_error;
    memcpy(mutated, base_der, (size_t)base_len);
    if (suffix->len > 0)
        memcpy(mutated + base_len, suffix->bytes, suffix->len);
    if (suffix->append_second_der)
        memcpy(mutated + base_len, base_der, (size_t)base_len);

    if (!b64_roundtrip(mutated, total_len, &decoded, &decoded_len))
        goto harness_error;

    p = decoded;
    pkey = d2i_PUBKEY_ex(NULL, &p, decoded_len, NULL, NULL);
    consumed_len = pkey != NULL ? (long)(p - decoded) : 0;

    printf("[CASE] pubkey_der/%s\n", suffix->name);
    printf("[INPUT_KIND] pubkey_der_b64_roundtrip\n");
    printf("[MUTATION] suffix_kind=%s\n", suffix->name);
    printf("[RESULT] baseline=%d\n", baseline);
    printf("[RESULT] d2i_success=%d\n", pkey != NULL);
    printf("[RESULT] decoded_len=%d\n", decoded_len);
    printf("[RESULT] consumed_len=%ld\n", consumed_len);
    printf("[RESULT] trailing_len=%zu\n", trailing_len);
    if (baseline && pkey != NULL && consumed_len == decoded_len)
        printf("[VERDICT] expected_baseline_accept\n\n");
    else if (pkey != NULL && consumed_len < decoded_len)
        printf("[VERDICT] ct_b64_pattern_accepts_trailing_garbage\n\n");
    else if (pkey != NULL)
        printf("[VERDICT] unexpected_full_consumption\n\n");
    else
        printf("[VERDICT] decode_rejects_input\n\n");

    EVP_PKEY_free(pkey);
    OPENSSL_free(decoded);
    OPENSSL_free(mutated);
    return;

harness_error:
    printf("[CASE] pubkey_der/%s\n", suffix->name);
    printf("[INPUT_KIND] pubkey_der_b64_roundtrip\n");
    printf("[MUTATION] suffix_kind=%s\n", suffix->name);
    printf("[RESULT] baseline=%d\n", baseline);
    printf("[RESULT] d2i_success=0\n");
    printf("[RESULT] decoded_len=0\n");
    printf("[RESULT] consumed_len=0\n");
    printf("[RESULT] trailing_len=%zu\n", trailing_len);
    printf("[VERDICT] harness_error\n\n");
    OPENSSL_free(decoded);
    OPENSSL_free(mutated);
}

int main(void)
{
    unsigned char *pub_der = NULL;
    int pub_der_len = 0;

    if (!make_pubkey_der(&pub_der, &pub_der_len)) {
        fprintf(stderr, "failed to generate PUBKEY DER\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }

    for (size_t i = 0; i < sizeof(SUFFIXES) / sizeof(SUFFIXES[0]); i++)
        run_case(pub_der, pub_der_len, &SUFFIXES[i]);

    OPENSSL_free(pub_der);
    return 0;
}
