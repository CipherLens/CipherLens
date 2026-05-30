#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/private/bignum.h"

#define A_LITERAL "[A_VALUE]"
#define B_LITERAL "[B_VALUE]"
#define A_BASE_VALUE [A_BASE]
#define B_BASE_VALUE [B_BASE]

int main(void)
{
    int ret = 0;
    int cmp = 0;
    mbedtls_mpi A;
    mbedtls_mpi B;
    mbedtls_mpi X;

    setbuf(stdout, NULL);

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&X);

    ret = mbedtls_mpi_read_string(&A, A_BASE_VALUE, A_LITERAL);
    if (ret != 0) {
        printf("[ERROR] source read A failed: %d\n", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_read_string(&B, B_BASE_VALUE, B_LITERAL);
    if (ret != 0) {
        printf("[ERROR] source read B failed: %d\n", ret);
        goto cleanup;
    }

    cmp = mbedtls_mpi_cmp_abs(&A, &B);
    ret = mbedtls_mpi_sub_abs(&X, &A, &B);

    printf("template_mutation A_VALUE=%s\n", A_LITERAL);
    printf("template_mutation B_VALUE=%s\n", B_LITERAL);
    printf("template_mutation A_BASE=%d\n", A_BASE_VALUE);
    printf("template_mutation B_BASE=%d\n", B_BASE_VALUE);
    printf("source_cmp=%d\n", cmp);
    printf("ret=%d\n", ret);

    if (cmp < 0 && ret != 0) {
        printf("[OK] source rejected negative mbedTLS absolute subtraction. ret=%d\n", ret);
        ret = 0;
        goto cleanup;
    }

    if (cmp < 0 && ret == 0) {
        printf("[TRIAGE] source produced result for negative mbedTLS absolute subtraction; semantic projection needs review.\n");
        ret = 2;
        goto cleanup;
    }

    printf("[INFO] source lhs>=rhs normal mbedTLS sub_abs path. ret=%d\n", ret);
    ret = 0;

cleanup:
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    return ret;
}
