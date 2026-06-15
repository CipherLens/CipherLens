/*
 * Family-level canonical wolfSSL template.
 *
 * family: asn1_nested_boundary
 * seed evidence: WOLFSSL-POC-0004
 *
 * This file models nested ASN.1/X.509 substructure boundary behavior.  It is
 * a canonical source template for mutation planning, not a runnable claim.
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/bio.h>

static const unsigned char der_bytes[] = {
    0x30, 0x03, 0x02, 0x01, 0x00
    /* [DER_BYTES] [ASN1_NESTED_LENGTH] [NESTED_DEPTH] */
};

int main(void)
{
    const unsigned char* p = der_bytes;
    int der_len = (int)sizeof(der_bytes); /* [DER_LENGTH] */
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL_BIO* bio = NULL;
    int ret = -1;

    /* trigger_call: preserve source parser path and nested ASN.1 boundary. */
    x509 = wolfSSL_X509_d2i(NULL, &p, der_len);
    if (x509 == NULL) {
        return 0; /* [EXPECT_RET]: safe reject */
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        wolfSSL_X509_free(x509);
        return 2;
    }

    /* trigger_call: preserve conversion path used by the seed evidence. */
    ret = wolfSSL_i2d_X509_bio(bio, x509);

    /* oracle_check: reject/accept/sanitizer observation, not exploit claim. */
    if (ret > 0) {
        wolfSSL_BIO_free(bio);
        wolfSSL_X509_free(x509);
        return 10; /* [EXPECT_RET] */
    }

    wolfSSL_BIO_free(bio); /* cleanup_call */
    wolfSSL_X509_free(x509); /* cleanup_call */
    return 0;
}
