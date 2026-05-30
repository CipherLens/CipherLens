#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "mbedtls/rsa.h"
#include "mbedtls/version.h"

/*
 * These parser functions exist in library/rsa.c in this version,
 * but the public header may not expose their prototypes directly
 * under the current configuration.
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

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bin(const char *hex, unsigned char *out, size_t out_size, size_t *out_len)
{
    size_t n = 0;
    int hi = -1;

    while (*hex != '\0') {
        if (isspace((unsigned char) *hex)) {
            hex++;
            continue;
        }

        int v = hexval((unsigned char) *hex);
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

static int test_private_key(void)
{
    int ret;
    unsigned char der[512];
    size_t der_len = 0;
    mbedtls_rsa_context rsa;

    /*
     * Regression-test-derived:
     * RSA parse private key - correct values, extra integer outside the SEQUENCE
     *
     * The trailing bytes are outside the top-level RSAPrivateKey SEQUENCE.
     */
    const char *hex =
        "3063020100021100cc8ab070369ede72920e5a51523c8571"
        "02030100010211009a6318982a7231de1894c54aa4909201"
        "020900f3058fd8dc484d61020900d7770dbd8b78a2110209"
        "009471f14c26428401020813425f060c4b72210208052b93"
        "d01747a87c020100";

    ret = hex_to_bin(hex, der, sizeof(der), &der_len);
    if (ret != 0) {
        printf("hex_to_bin private failed: %d\n", ret);
        return 2;
    }

    rsa_init_compat(&rsa);

    ret = mbedtls_rsa_parse_key(&rsa, der, der_len);

    printf("private ret=%d\n", ret);
    printf("private expected_buggy=0\n");
    printf("private expected_fixed=%d\n", MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

    if (ret == 0) {
        printf("[BUG] private key parser accepted trailing garbage.\n");
    } else if (ret == MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        printf("[OK] private key parser rejected trailing garbage.\n");
    } else {
        printf("[INFO] private key parser returned unexpected ret=%d\n", ret);
    }

    mbedtls_rsa_free(&rsa);
    return ret;
}

static int test_public_key(void)
{
    int ret;
    unsigned char der[512];
    size_t der_len = 0;
    mbedtls_rsa_context rsa;

    /*
     * Regression-test-derived:
     * RSA parse public key - correct values, extra integer outside the SEQUENCE
     */
    const char *hex =
        "308189028181009f091e6968b474f76f0e9c237c1d895996"
        "ae704b4f6d706acec8d2daac6209bf524aa3f658d0283a"
        "dba1077f6cbe92e425dcde52290b239cade91be86c884254"
        "34986806e85734e159768f3dfea932baaa9409d25bace8ee"
        "9dce0cdde0903207299de575ae60feccf0daf82334ab836"
        "38539b0da74072f253acea8afc8e66bb70203010001020100";

    ret = hex_to_bin(hex, der, sizeof(der), &der_len);
    if (ret != 0) {
        printf("hex_to_bin public failed: %d\n", ret);
        return 2;
    }

    rsa_init_compat(&rsa);

    ret = mbedtls_rsa_parse_pubkey(&rsa, der, der_len);

    printf("public ret=%d\n", ret);
    printf("public expected_buggy=0\n");
    printf("public expected_fixed=%d\n", MBEDTLS_ERR_RSA_BAD_INPUT_DATA);

    if (ret == 0) {
        printf("[BUG] public key parser accepted trailing garbage.\n");
    } else if (ret == MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        printf("[OK] public key parser rejected trailing garbage.\n");
    } else {
        printf("[INFO] public key parser returned unexpected ret=%d\n", ret);
    }

    mbedtls_rsa_free(&rsa);
    return ret;
}

int main(void)
{
    int ret_priv;
    int ret_pub;

    setbuf(stdout, NULL);

    printf("Testing RSA private key with trailing garbage...\n");
    ret_priv = test_private_key();

    printf("\nTesting RSA public key with trailing garbage...\n");
    ret_pub = test_public_key();

    if (ret_priv == 0 && ret_pub == 0) {
        printf("\n[BUG] both RSA parsers accepted trailing garbage.\n");
    } else if (ret_priv == MBEDTLS_ERR_RSA_BAD_INPUT_DATA &&
               ret_pub == MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        printf("\n[OK] both RSA parsers rejected trailing garbage.\n");
    } else {
        printf("\n[INFO] mixed or unexpected results: private=%d public=%d\n",
               ret_priv, ret_pub);
    }

    return 0;
}
