#include <stdio.h>
#include <string.h>

#include "mbedtls/pem.h"

#define PEM_BODY_CONTENT "[PEM_BODY]"

static const char malformed_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "Proc-Type: 4,ENCRYPTED\r\n"
    "DEK-Info: AES-128-CBC,AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB\r\n"
    "\r\n"
    PEM_BODY_CONTENT "\r\n"
    "-----END EC PRIVATE KEY-----\r\n";

int main(void)
{
    mbedtls_pem_context ctx;
    size_t use_len = 0;
    int ret;

    setbuf(stdout, NULL);

    mbedtls_pem_init(&ctx);

    printf("template_mutation PEM_BODY=%s\n", PEM_BODY_CONTENT);
    printf("calling mbedtls_pem_read_buffer...\n");

    /*
     * Historical bug (CVE-2025-52497 / mbedTLS 3.x buggy):
     *   malformed encrypted PEM with too-short base64 body decodes to
     *   empty or tiny buffer; pem_check_pkcs_padding() reads
     *   input[input_len - 1] without checking input_len >= 1,
     *   causing a one-byte heap-buffer-underflow (ASAN READ of size 1).
     *
     * Fixed behavior (current 4.x):
     *   early validation rejects malformed input safely with an error code.
     */
    ret = mbedtls_pem_read_buffer(
        &ctx,
        "-----BEGIN EC PRIVATE KEY-----",
        "-----END EC PRIVATE KEY-----",
        (const unsigned char *) malformed_pem,
        (const unsigned char *) "pwd",
        3,
        &use_len);

    printf("ret=%d\n", ret);
    printf("use_len=%zu\n", use_len);

    if (ret != 0) {
        printf("[OK] fixed behavior: malformed encrypted PEM rejected safely. ret=%d\n", ret);
    } else {
        printf("[INFO] unexpected success. use_len=%zu\n", use_len);
    }

    mbedtls_pem_free(&ctx);
    return 0;
}
