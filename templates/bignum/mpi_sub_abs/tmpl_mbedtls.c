/*
 * TEMPLATE: bignum/mpi_sub_abs/tmpl_mbedtls.c
 *
 * Source PoC:
 *   poc_mpi_sub_abs_min.c
 *
 * API:
 *   mbedtls_mpi_sub_abs
 *
 * Bug pattern:
 *   A < B + manually undersized X limb buffer + canary check
 *
 * MUTATION_POINTS:
 *   A_VALUE      = [A_VALUE]       default "5"
 *   B_VALUE      = [B_VALUE]       default "123456789abcdef01"
 *   A_BASE       = [A_BASE]        default 10
 *   B_BASE       = [B_BASE]        default 16
 *   X_LIMB_COUNT = [X_LIMB_COUNT]  default 1
 *   CANARY_SIZE  = [CANARY_SIZE]   default 16
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/bignum.h"

#define CANARY_SIZE [CANARY_SIZE]
#define CANARY_BYTE 0xA5

static int canary_corrupted(mbedtls_mpi *X)
{
    if (X->p == NULL || X->n == 0) {
        return 0;
    }

    unsigned char *raw = (unsigned char *) X->p;
    size_t used = X->n * sizeof(mbedtls_mpi_uint);

    for (size_t i = 0; i < CANARY_SIZE; i++) {
        if (raw[used + i] != CANARY_BYTE) {
            return 1;
        }
    }

    return 0;
}

static int prepare_output_with_canary(mbedtls_mpi *X, size_t limbs)
{
    size_t alloc_size = limbs * sizeof(mbedtls_mpi_uint) + CANARY_SIZE;
    unsigned char *raw = (unsigned char *) calloc(1, alloc_size);

    if (raw == NULL) {
        return -1;
    }

    memset(raw + limbs * sizeof(mbedtls_mpi_uint), CANARY_BYTE, CANARY_SIZE);

    X->s = 1;
    X->n = limbs;
    X->p = (mbedtls_mpi_uint *) raw;

    return 0;
}

int main(void)
{
    int ret;
    mbedtls_mpi X;
    mbedtls_mpi A;
    mbedtls_mpi B;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);

    ret = mbedtls_mpi_read_string(&A, [A_BASE], "[A_VALUE]");
    if (ret != 0) {
        printf("read A failed: %d\n", ret);
        goto cleanup_no_free_xp;
    }

    ret = mbedtls_mpi_read_string(&B, [B_BASE], "[B_VALUE]");
    if (ret != 0) {
        printf("read B failed: %d\n", ret);
        goto cleanup_no_free_xp;
    }

    if (prepare_output_with_canary(&X, [X_LIMB_COUNT]) != 0) {
        printf("prepare_output_with_canary failed\n");
        ret = 2;
        goto cleanup_no_free_xp;
    }

    printf("A.n=%zu B.n=%zu X.n=%zu sizeof(mbedtls_mpi_uint)=%zu\n",
           A.n, B.n, X.n, sizeof(mbedtls_mpi_uint));

    ret = mbedtls_mpi_sub_abs(&X, &A, &B);

    printf("ret=%d\n", ret);
    printf("expected=%d\n", MBEDTLS_ERR_MPI_NEGATIVE_VALUE);

    if (canary_corrupted(&X)) {
        printf("[BUG] Canary corrupted: mbedtls_mpi_sub_abs wrote beyond X->p.\n");
        ret = 1;
    } else {
        printf("[OK] Canary intact.\n");
    }

    free(X.p);
    X.p = NULL;
    X.n = 0;

cleanup_no_free_xp:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);

    return ret == 1 ? 1 : 0;
}
