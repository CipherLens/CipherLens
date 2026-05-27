#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"

#define BUFLEN 4
#define CANARY_SIZE 16
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf)
{
    for (size_t i = 0; i < CANARY_SIZE; i++) {
        if (buf[BUFLEN + i] != CANARY_BYTE) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    mbedtls_mpi X;
    unsigned char buf[BUFLEN + CANARY_SIZE];
    size_t olen = 0;
    int ret;

    memset(buf, 0x42, sizeof(buf));
    memset(buf + BUFLEN, CANARY_BYTE, CANARY_SIZE);

    mbedtls_mpi_init(&X);

    ret = mbedtls_mpi_lset(&X, -1);
    if (ret != 0) {
        printf("mbedtls_mpi_lset failed: %d\n", ret);
        mbedtls_mpi_free(&X);
        return 2;
    }

    ret = mbedtls_mpi_write_string(
        &X,
        2,
        (char *) buf,
        BUFLEN,
        &olen
    );

    printf("ret=%d\n", ret);
    printf("olen=%zu\n", olen);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            printf("%c", c);
        } else {
            printf("\\x%02x", c);
        }
    }
    printf("\n");

    if (canary_corrupted(buf)) {
        printf("[BUG] Canary corrupted: out-of-bounds write detected.\n");
        mbedtls_mpi_free(&X);
        return 1;
    }

    printf("[OK] Canary intact.\n");

    mbedtls_mpi_free(&X);
    return 0;
}
