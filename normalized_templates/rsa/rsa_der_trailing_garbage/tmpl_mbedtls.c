/*
 * Normalized template for MBEDTLS-POC-0020:
 * RSA DER parser accepts trailing garbage after the top-level SEQUENCE.
 *
 * Source public API: mbedtls_pk_parse_key
 * Internal isolation APIs: mbedtls_rsa_parse_key, mbedtls_rsa_parse_pubkey
 *
 * Mask anchors:
 * - [DER_KIND]
 * - [PARSE_API_KIND]
 * - [TRAILING_GARBAGE_BYTES]
 * - [TRAILING_GARBAGE_LEN]
 * - [EXPECT_RET]
 * - [TOP_LEVEL_SEQUENCE_END_CHECK]
 * - [RSA_PRIVATE_PARSE_CALL]
 * - [RSA_PUBLIC_PARSE_CALL]
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/version.h"

/*
 * These functions are present in the mbedTLS RSA parser implementation used by
 * the source PoC, but may not be declared by the public headers under all build
 * configurations. The normalized source API remains mbedtls_pk_parse_key.
 */
int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa,
                          const unsigned char *key,
                          size_t keylen);

int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context *rsa,
                             const unsigned char *key,
                             size_t keylen);

#ifndef MBEDTLS_ERR_RSA_BAD_INPUT_DATA
#error "MBEDTLS_ERR_RSA_BAD_INPUT_DATA is not defined"
#endif

#define DER_KIND_VALUE "[DER_KIND]"
#define PARSE_API_KIND_VALUE "[PARSE_API_KIND]"
#define TRAILING_GARBAGE_HEX "[TRAILING_GARBAGE_BYTES]"
#define TRAILING_GARBAGE_EXPECTED_LEN ((size_t) [TRAILING_GARBAGE_LEN])
#define EXPECTED_RETURN_VALUE [EXPECT_RET]

static int hexval(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int hex_to_bin(const char *hex,
                      unsigned char *out,
                      size_t out_size,
                      size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    while (*hex != '\0') {
        int v;

        if (isspace((unsigned char) *hex)) {
            hex++;
            continue;
        }

        v = hexval((unsigned char) *hex);
        if (v < 0) {
            return -1;
        }

        if (hi < 0) {
            hi = v;
        } else {
            if (n >= out_size) {
                return -2;
            }
            out[n++] = (unsigned char) ((hi << 4) | v);
            hi = -1;
        }

        hex++;
    }

    if (hi >= 0) {
        return -3;
    }

    *out_len = n;
    return 0;
}

static void rsa_init_compat(mbedtls_rsa_context *rsa)
{
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER < 0x03000000
    mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);
#else
    mbedtls_rsa_init(rsa);
#endif
}

static const char *select_base_der_hex(const char *der_kind)
{
    /*
     * Regression-test-derived minimal private key from
     * data/pocs/core10/MBEDTLS-POC-0020/poc/poc_rsa_trailing_garbage.c,
     * with the top-level trailing INTEGER removed. The base object is a
     * complete PKCS#1 RSAPrivateKey SEQUENCE.
     */
    static const char *private_base_hex =
        "3063020100021100cc8ab070369ede72920e5a51523c8571"
        "02030100010211009a6318982a7231de1894c54aa4909201"
        "020900f3058fd8dc484d61020900d7770dbd8b78a2110209"
        "009471f14c26428401020813425f060c4b72210208052b93"
        "d01747a87c";

    /*
     * Regression-test-derived minimal public key from the same source PoC,
     * with the top-level trailing INTEGER removed. The base object is a
     * complete PKCS#1 RSAPublicKey SEQUENCE.
     */
    static const char *public_base_hex =
        "308189028181009f091e6968b474f76f0e9c237c1d895996"
        "ae704b4f6d706acec8d2daac6209bf524aa3f658d0283a"
        "dba1077f6cbe92e425dcde52290b239cade91be86c884254"
        "34986806e85734e159768f3dfea932baaa9409d25bace8ee"
        "9dce0cdde0903207299de575ae60feccf0daf82334ab836"
        "38539b0da74072f253acea8afc8e66bb70203010001";

    if (strcmp(der_kind, "private") == 0) {
        return private_base_hex;
    }
    if (strcmp(der_kind, "public") == 0) {
        return public_base_hex;
    }

    return NULL;
}

static int build_der_with_trailing_garbage(const char *base_hex,
                                           const char *trailing_hex,
                                           unsigned char *der,
                                           size_t der_size,
                                           size_t *der_len,
                                           size_t *trailing_len)
{
    int ret;
    size_t base_len = 0;

    ret = hex_to_bin(base_hex, der, der_size, &base_len);
    if (ret != 0) {
        return ret;
    }

    ret = hex_to_bin(trailing_hex,
                     der + base_len,
                     der_size - base_len,
                     trailing_len);
    if (ret != 0) {
        return ret;
    }

    *der_len = base_len + *trailing_len;
    return 0;
}

static int parse_with_selected_api(const char *parse_api_kind,
                                   const char *der_kind,
                                   const unsigned char *der,
                                   size_t der_len)
{
    int ret = -1;

    if (strcmp(parse_api_kind, "rsa_private") == 0) {
        mbedtls_rsa_context rsa;

        rsa_init_compat(&rsa);
        /* [RSA_PRIVATE_PARSE_CALL] */
        ret = mbedtls_rsa_parse_key(&rsa, der, der_len);
        mbedtls_rsa_free(&rsa);
        return ret;
    }

    if (strcmp(parse_api_kind, "rsa_public") == 0) {
        mbedtls_rsa_context rsa;

        rsa_init_compat(&rsa);
        /* [RSA_PUBLIC_PARSE_CALL] */
        ret = mbedtls_rsa_parse_pubkey(&rsa, der, der_len);
        mbedtls_rsa_free(&rsa);
        return ret;
    }

    if (strcmp(parse_api_kind, "pk_private") == 0) {
        mbedtls_pk_context pk;

        if (strcmp(der_kind, "private") != 0) {
            return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        }

        mbedtls_pk_init(&pk);
        ret = mbedtls_pk_parse_key(&pk, der, der_len, NULL, 0);
        mbedtls_pk_free(&pk);
        return ret;
    }

    return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
}

int main(void)
{
    const char *der_kind = DER_KIND_VALUE;
    const char *parse_api_kind = PARSE_API_KIND_VALUE;
    const char *base_hex = NULL;
    unsigned char *der = NULL;
    const size_t der_capacity = 512;
    size_t der_len = 0;
    size_t trailing_len = 0;
    int ret;

    setbuf(stdout, NULL);

    base_hex = select_base_der_hex(der_kind);
    if (base_hex == NULL) {
        printf("[ERROR] unsupported DER_KIND: %s\n", der_kind);
        return 2;
    }

    der = calloc(der_capacity, 1);
    if (der == NULL) {
        printf("[ERROR] allocation failed\n");
        return 2;
    }

    ret = build_der_with_trailing_garbage(base_hex,
                                          TRAILING_GARBAGE_HEX,
                                          der,
                                          der_capacity,
                                          &der_len,
                                          &trailing_len);
    if (ret != 0) {
        printf("[ERROR] DER construction failed: %d\n", ret);
        free(der);
        return 2;
    }

    if (trailing_len != TRAILING_GARBAGE_EXPECTED_LEN) {
        printf("[ERROR] trailing garbage length mismatch: got=%zu expected=%zu\n",
               trailing_len, TRAILING_GARBAGE_EXPECTED_LEN);
        free(der);
        return 2;
    }

    printf("DER kind: %s\n", der_kind);
    printf("Parse API kind: %s\n", parse_api_kind);
    printf("DER length with trailing garbage: %zu\n", der_len);
    printf("Trailing garbage length: %zu\n", trailing_len);

    /*
     * Fixed source guard represented by [TOP_LEVEL_SEQUENCE_END_CHECK]:
     * if (end != p + len) { return MBEDTLS_ERR_RSA_BAD_INPUT_DATA; }
     */
    ret = parse_with_selected_api(parse_api_kind, der_kind, der, der_len);

    printf("ret=%d\n", ret);
    printf("expected_buggy=0\n");
    printf("expected_fixed_or_safe=%d\n", EXPECTED_RETURN_VALUE);

    if (ret == 0) {
        printf("[BUG] parser accepted trailing garbage after top-level SEQUENCE.\n");
        free(der);
        return 1;
    }

    if (ret == EXPECTED_RETURN_VALUE ||
        ret == MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        printf("[OK] parser rejected trailing garbage.\n");
        free(der);
        return 0;
    }

    printf("[INFO] parser rejected trailing garbage with alternate ret=%d\n", ret);
    free(der);
    return 0;
}
