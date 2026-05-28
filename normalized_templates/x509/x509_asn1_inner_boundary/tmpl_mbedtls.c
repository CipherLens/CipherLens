#include <stdio.h>
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#define INNER_END_BOUND_MODE "[INNER_END_BOUND]"
#define TRAILING_INNER_DATA_CHECK_MODE "[TRAILING_INNER_DATA_CHECK]"
#define EMPTY_EXTENSION_RETURN_MODE "[EMPTY_EXTENSION_RETURN]"
#define MALFORMED_DER_STRUCTURE_MODE "[MALFORMED_DER_STRUCTURE]"

/*
 * Template for MBEDTLS-POC-0017.
 *
 * Placeholders:
 * - [INNER_END_BOUND]
 * - [TRAILING_INNER_DATA_CHECK]
 * - [EMPTY_EXTENSION_RETURN]
 * - [MALFORMED_DER_STRUCTURE]
 *
 * The concrete DER below is copied from the local minimal PoC. It models a
 * malformed X.509 certificate whose issuer contains empty inner
 * AttributeTypeAndValue structures.
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
    int ret;
    int expected_buggy;
    int expected_fixed;
    size_t der_len = 0;
    const unsigned char *der = NULL;
    mbedtls_x509_crt crt;

    setbuf(stdout, NULL);

    expected_buggy = MBEDTLS_ERR_X509_INVALID_NAME +
                     MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    expected_fixed = MBEDTLS_ERR_X509_INVALID_NAME +
                     MBEDTLS_ERR_ASN1_OUT_OF_DATA;

    der = select_malformed_der(MALFORMED_DER_STRUCTURE_MODE, &der_len);
    if (der == NULL || der_len == 0) {
        printf("[ERROR] malformed DER construction failed.\n");
        return 2;
    }

    printf("template_mutation INNER_END_BOUND=%s\n", INNER_END_BOUND_MODE);
    printf("template_mutation TRAILING_INNER_DATA_CHECK=%s\n", TRAILING_INNER_DATA_CHECK_MODE);
    printf("template_mutation EMPTY_EXTENSION_RETURN=%s\n", EMPTY_EXTENSION_RETURN_MODE);
    printf("template_mutation MALFORMED_DER_STRUCTURE=%s\n", MALFORMED_DER_STRUCTURE_MODE);
    printf("calling mbedtls_x509_crt_parse_der...\n");
    printf("der_len=%zu\n", der_len);

    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse_der(&crt, der, der_len);

    printf("ret=%d\n", ret);
    printf("expected_buggy=%d\n", expected_buggy);
    printf("expected_fixed=%d\n", expected_fixed);

    if (ret == expected_fixed) {
        printf("[OK] fixed behavior: parser obeyed inner ASN.1 substructure bounds.\n");
        mbedtls_x509_crt_free(&crt);
        return 0;
    }

    if (ret == expected_buggy) {
        printf("[BUG] buggy behavior: parser crossed inner ASN.1 substructure bounds.\n");
        mbedtls_x509_crt_free(&crt);
        return 1;
    }

    printf("[INFO] unexpected behavior: ret=%d\n", ret);
    mbedtls_x509_crt_free(&crt);
    return 0;
}
