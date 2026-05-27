/*
 * TEMPLATE: bignum/mpi_sub_abs/tmpl_openssl.c
 *
 * Migration from:
 *   mbedtls_mpi_sub_abs limb-boundary canary template
 *
 * Candidate API:
 *   BN_usub
 *
 * Important:
 *   This is a candidate migration harness. It does not assume OpenSSL has the
 *   same vulnerability path. It checks how OpenSSL behaves when unsigned
 *   subtraction is requested with A < B.
 *
 * MUTATION_POINTS:
 *   A_VALUE = [A_VALUE]
 *   B_VALUE = [B_VALUE]
 *   A_BASE  = [A_BASE]
 *   B_BASE  = [B_BASE]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/bn.h"

static int set_bn_from_string(BIGNUM **out, int base, const char *value)
{
    if (base == 10) {
        return BN_dec2bn(out, value);
    }

    if (base == 16) {
        return BN_hex2bn(out, value);
    }

    /*
     * OpenSSL does not provide direct BN_bin/BN_oct parser by radix string here.
     * Unsupported bases are treated as harness construction errors.
     */
    return 0;
}

int main(void)
{
    int ret = 0;

    BIGNUM *A = BN_new();
    BIGNUM *B = BN_new();
    BIGNUM *R = BN_new();

    if (A == NULL || B == NULL || R == NULL) {
        printf("BN_new failed\n");
        ret = 2;
        goto cleanup;
    }

    if (set_bn_from_string(&A, [A_BASE], "[A_VALUE]") == 0) {
        printf("read A failed\n");
        ret = 2;
        goto cleanup;
    }

    if (set_bn_from_string(&B, [B_BASE], "[B_VALUE]") == 0) {
        printf("read B failed\n");
        ret = 2;
        goto cleanup;
    }

    printf("BN_num_bits(A)=%d BN_num_bits(B)=%d\n",
           BN_num_bits(A), BN_num_bits(B));

    /*
     * Candidate trigger:
     * BN_usub performs unsigned subtraction. A < B should not be silently
     * accepted as a valid non-negative result.
     */
    ret = BN_usub(R, A, B);

    if (ret == 1) {
        char *r_str = BN_bn2dec(R);
        printf("[DIFF] BN_usub accepted A < B, result=%s\n",
               r_str != NULL ? r_str : "null");
        OPENSSL_free(r_str);
        ret = 2;
        goto cleanup;
    }

    printf("[OK] BN_usub rejected A < B or returned failure, ret=%d\n", ret);
    ret = 0;

cleanup:
    BN_free(A);
    BN_free(B);
    BN_free(R);

    return ret;
}
