#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MALFORMED_DER_STRUCTURE_MODE "[MALFORMED_DER_STRUCTURE]"

/*
 * Cross-library harness for MBEDTLS-POC-0017.
 *
 * Source mbedTLS oracle:
 * - buggy signal: ret=-9186
 * - fixed signal: ret=-9184
 *
 * OpenSSL d2i_X509 does not expose the same internal mbedTLS error codes.
 * This harness observes return-code and input-pointer consumption semantics.
 */

static const unsigned char *select_malformed_der(const char *structure_id,
                                                 size_t *der_len)
{
    static const unsigned char issuer_two_empty_atv_der[] = {
        0x30, 0x24, 0x30, 0x22,
        0xa0, 0x03, 0x02, 0x01, 0x02,
        0x82, 0x04, 0xde, 0xad, 0xbe, 0xef,
        0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
        0x05, 0x00,
        0x30, 0x06,
        0x31, 0x04,
        0x30, 0x00,
        0x30, 0x00
    };

    if (der_len == NULL) {
        return NULL;
    }

    if (strcmp(structure_id, "issuer_two_empty_atv") == 0 ||
        strcmp(structure_id, "default") == 0) {
        *der_len = sizeof(issuer_two_empty_atv_der);
        return issuer_two_empty_atv_der;
    }

    *der_len = sizeof(issuer_two_empty_atv_der);
    return issuer_two_empty_atv_der;
}

int main(void)
{
    const unsigned char *der = NULL;
    size_t der_len = 0;
    int ret = 0;

    setbuf(stdout, NULL);

    der = select_malformed_der(MALFORMED_DER_STRUCTURE_MODE, &der_len);
    if (der == NULL || der_len == 0) {
        printf("[ERROR] malformed DER construction failed.\n");
        return 2;
    }

    printf("template_mutation MALFORMED_DER_STRUCTURE=%s\n", MALFORMED_DER_STRUCTURE_MODE);
    printf("calling d2i_X509...\n");
    printf("der_len=%zu\n", der_len);

    /*
     * Adapter-generated initialization.
     */
    X509 *x509 = NULL;
    const unsigned char *p = NULL;
    long consumed_len = 0;

    /*
     * Adapter-generated input construction.
     */
    p = der;
    consumed_len = 0;

    /*
     * Adapter-generated trigger call.
     * target_api: d2i_X509
     */
    x509 = d2i_X509(NULL, &p, der_len);
    ret = (x509 != NULL) ? 0 : -1;
    consumed_len = (long)(p - der);

    printf("ret=%d\n", ret);
    printf("consumed_len=%ld\n", consumed_len);
    printf("der_len=%zu\n", der_len);

    if (ret == 0) {
        printf("[BUG] target accepted malformed X509/ASN1 inner-boundary input. consumed_len=%ld der_len=%zu\n",
               consumed_len, der_len);
        X509_free(x509);
        return 1;
    }

    printf("[OK] target rejected malformed X509/ASN1 inner-boundary input.\n");
    X509_free(x509);
    return 0;
}
