#include <stdio.h>
#include <string.h>

#include "mbedtls/x509_crt.h"
#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"

/*
 * Minimal PoC for MBEDTLS-POC-0017 / PR #2442.
 *
 * Regression-test-derived DER:
 * X509 Certificate ASN1 (TBSCertificate, issuer two inner set datas)
 *
 * Buggy behavior:
 *   The parser does not restrict ASN.1 parsing to the inner substructure bounds
 *   and reports MBEDTLS_ERR_ASN1_UNEXPECTED_TAG.
 *
 * Fixed behavior:
 *   The parser obeys the zero-length inner substructure bounds and reports
 *   MBEDTLS_ERR_ASN1_OUT_OF_DATA.
 */

int main(void)
{
    int ret;
    int expected_buggy;
    int expected_fixed;

    mbedtls_x509_crt crt;

    const unsigned char der[] = {
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

    setbuf(stdout, NULL);

    expected_buggy = MBEDTLS_ERR_X509_INVALID_NAME +
                     MBEDTLS_ERR_ASN1_UNEXPECTED_TAG;
    expected_fixed = MBEDTLS_ERR_X509_INVALID_NAME +
                     MBEDTLS_ERR_ASN1_OUT_OF_DATA;

    mbedtls_x509_crt_init(&crt);

    printf("calling mbedtls_x509_crt_parse_der...\n");

    ret = mbedtls_x509_crt_parse_der(&crt, der, sizeof(der));

    printf("ret=%d\n", ret);
    printf("expected_buggy=%d\n", expected_buggy);
    printf("expected_fixed=%d\n", expected_fixed);

    if (ret == expected_fixed) {
        printf("[OK] fixed behavior: parser obeyed inner ASN.1 substructure bounds.\n");
    } else if (ret == expected_buggy) {
        printf("[BUG] buggy behavior: parser crossed inner ASN.1 substructure bounds.\n");
    } else {
        printf("[INFO] unexpected behavior: ret=%d\n", ret);
    }

    mbedtls_x509_crt_free(&crt);
    return 0;
}
