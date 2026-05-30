#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_DER_SIZE 1024
#define TRAILING_GARBAGE_HEX "[TRAILING_GARBAGE_BYTES]"
#define TRAILING_GARBAGE_EXPECTED_LEN ((size_t) [TRAILING_GARBAGE_LEN])

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

int main(void)
{
    const char *der_kind = "[DER_KIND]";
    const char *base_hex = NULL;
    unsigned char der[MAX_DER_SIZE];
    size_t der_len = 0;
    size_t trailing_len = 0;
    const unsigned char *p = NULL;
    long consumed_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);
    memset(der, 0, sizeof(der));

    base_hex = select_base_der_hex(der_kind);
    if (base_hex == NULL) {
        printf("[ERROR] unsupported DER_KIND: %s\n", der_kind);
        return 2;
    }

    ret = build_der_with_trailing_garbage(base_hex,
                                          TRAILING_GARBAGE_HEX,
                                          der,
                                          sizeof(der),
                                          &der_len,
                                          &trailing_len);
    if (ret != 0) {
        printf("[ERROR] DER construction failed: %d\n", ret);
        return 2;
    }

    if (trailing_len != TRAILING_GARBAGE_EXPECTED_LEN) {
        printf("[ERROR] trailing garbage length mismatch: got=%zu expected=%zu\n",
               trailing_len, TRAILING_GARBAGE_EXPECTED_LEN);
        return 2;
    }

    /*
     * Adapter-generated initialization.
     */
    RSA *rsa = NULL;

    /*
     * Adapter-generated input construction.
     */
    p = der;
    consumed_len = 0;

    /*
     * Adapter-generated trigger call.
     * target_api: d2i_RSA_PUBKEY
     */
    rsa = d2i_RSA_PUBKEY(NULL, &p, der_len);
    ret = (rsa != NULL) ? 0 : -1;
    consumed_len = (long)(p - der);

    printf("ret=%d\n", ret);
    printf("der_len=%zu\n", der_len);
    printf("consumed_len=%ld\n", consumed_len);

    if (ret == 0 && consumed_len < (long) der_len) {
        printf("[BUG] target decoded first DER object but left trailing garbage unconsumed.\n");
        RSA_free(rsa);
        return 1;
    }

    if (ret == 0 && consumed_len == (long) der_len) {
        printf("[OK] target decoded and consumed full input exactly.\n");
        RSA_free(rsa);
        return 0;
    }

    printf("[OK] target rejected trailing-garbage input.\n");
    RSA_free(rsa);
    return 0;
}
