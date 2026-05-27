/*
 * TEMPLATE: bignum/mpi_write_string/tmpl_mbedtls.c
 *
 * Source PoC:
 *   poc_mpi_write_string_min.c
 *
 * API:
 *   mbedtls_mpi_write_string
 *
 * Bug pattern:
 *   negative MPI value + undersized output buffer + canary check
 *
 * MUTATION_POINTS:
 *   VALUE       = [VALUE]          default -1
 *   RADIX       = [RADIX]          default 2
 *   BUFLEN      = [BUFLEN]         default 4
 *   CANARY_SIZE = [CANARY_SIZE]    default 16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"

#define BUFLEN [BUFLEN]
#define CANARY_SIZE [CANARY_SIZE]
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

    ret = mbedtls_mpi_lset(&X, [VALUE]);
    if (ret != 0) {
        printf("mbedtls_mpi_lset failed: %d\n", ret);
        mbedtls_mpi_free(&X);
        return 2;
    }

    ret = mbedtls_mpi_write_string(
        &X,
        [RADIX],
        (char *) buf,
        BUFLEN,
        &olen
    );

    printf("ret=%d\n", ret);
    printf("olen=%zu\n", olen);
    printf("buf/canary prefix=");

    for (size_t i = 0; i < BUFLEN + 8 && i < BUFLEN + CANARY_SIZE; i++) {
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
