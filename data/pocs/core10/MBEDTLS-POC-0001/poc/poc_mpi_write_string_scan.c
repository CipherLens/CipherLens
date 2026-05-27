#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"

#define CANARY_SIZE 16
#define CANARY_BYTE 0xA5

static int canary_corrupted(unsigned char *buf, size_t buflen)
{
    for (size_t i = 0; i < CANARY_SIZE; i++) {
        if (buf[buflen + i] != CANARY_BYTE) {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    int found = 0;

    for (long value = 1; value <= 1000000; value = value * 10 + 1) {
        for (int radix = 2; radix <= 16; radix++) {
            for (size_t buflen = 1; buflen <= 128; buflen++) {
                mbedtls_mpi X;
                size_t olen = 0;
                int ret;

                unsigned char *buf = (unsigned char *) malloc(buflen + CANARY_SIZE);
                if (buf == NULL) {
                    fprintf(stderr, "malloc failed\n");
                    return 2;
                }

                memset(buf, 0x42, buflen);
                memset(buf + buflen, CANARY_BYTE, CANARY_SIZE);

                mbedtls_mpi_init(&X);

                ret = mbedtls_mpi_lset(&X, -value);
                if (ret != 0) {
                    mbedtls_mpi_free(&X);
                    free(buf);
                    continue;
                }

                ret = mbedtls_mpi_write_string(
                    &X,
                    radix,
                    (char *) buf,
                    buflen,
                    &olen
                );

                if (canary_corrupted(buf, buflen)) {
                    printf("[!] Canary corrupted!\n");
                    printf("    value  = -%ld\n", value);
                    printf("    radix  = %d\n", radix);
                    printf("    buflen = %zu\n", buflen);
                    printf("    ret    = %d\n", ret);
                    printf("    olen   = %zu\n", olen);
                    printf("    buffer prefix: ");

                    for (size_t i = 0; i < buflen + 4 && i < buflen + CANARY_SIZE; i++) {
                        unsigned char c = buf[i];
                        if (c >= 32 && c <= 126) {
                            printf("%c", c);
                        } else {
                            printf("\\x%02x", c);
                        }
                    }
                    printf("\n");

                    found = 1;

                    mbedtls_mpi_free(&X);
                    free(buf);
                    return 1;
                }

                mbedtls_mpi_free(&X);
                free(buf);
            }
        }
    }

    if (!found) {
        printf("[+] No canary corruption detected in scanned range.\n");
    }

    return 0;
}
