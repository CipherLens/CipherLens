# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_ecp.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
*/
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi dA, xA, yA, dB, xZ, yZ;
    int cnt_restarts;
    int ret;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    /* Base point case */
    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dA, &grp.G,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);
```

## Call pattern 2

```c
mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi dA, xA, yA, dB, xZ, yZ;
    int cnt_restarts;
    int ret;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    /* Base point case */
    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dA, &grp.G,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
```

## Call pattern 3

```c
/* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dB, &P,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_RESTARTABLE:MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
void ecp_muladd_restart(int id, char *xR_str, char *yR_str,
                        char *u1_str, char *u2_str,
                        char *xQ_str, char *yQ_str,
                        int max_ops, int min_restarts, int max_restarts)
{
    /*
     * Compute R = u1 * G + u2 * Q
     * (test vectors mostly taken from ECDSA intermediate results)
     *
     * See comments at the top of ecp_test_vect_restart()
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&Q);
```

## Call pattern 4

```c
* This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_mul_restartable(&grp, &R, &dB, &P,
                                          &mbedtls_test_rnd_pseudo_rand, &rnd_info, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_RESTARTABLE:MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
void ecp_muladd_restart(int id, char *xR_str, char *yR_str,
                        char *u1_str, char *u2_str,
                        char *xQ_str, char *yQ_str,
                        int max_ops, int min_restarts, int max_restarts)
{
    /*
     * Compute R = u1 * G + u2 * Q
     * (test vectors mostly taken from ECDSA intermediate results)
     *
     * See comments at the top of ecp_test_vect_restart()
     */
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
```

## Call pattern 5

```c
*/
    mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
    mbedtls_mpi_init(&xR); mbedtls_mpi_init(&yR);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&u1, u1_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&u2, u2_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xR, xR_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yR, yR_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&Q.X, xQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q.Y, yQ_str) == 0);
    TEST_ASSERT(mbedtls_mpi_lset(&Q.Z, 1) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xR) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yR) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
```

## Call pattern 6

```c
mbedtls_ecp_restart_ctx ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, Q;
    mbedtls_mpi u1, u2, xR, yR;
    int cnt_restarts;
    int ret;

    mbedtls_ecp_restart_init(&ctx);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
    mbedtls_mpi_init(&xR); mbedtls_mpi_init(&yR);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&u1, u1_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&u2, u2_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xR, xR_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yR, yR_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&Q.X, xQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q.Y, yQ_str) == 0);
    TEST_ASSERT(mbedtls_mpi_lset(&Q.Z, 1) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xR) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yR) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
    TEST_ASSERT(cnt_restarts <= max_restarts);
```

## Call pattern 7

```c
mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
    mbedtls_mpi_init(&xR); mbedtls_mpi_init(&yR);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&u1, u1_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&u2, u2_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xR, xR_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yR, yR_str) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&Q.X, xQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Q.Y, yQ_str) == 0);
    TEST_ASSERT(mbedtls_mpi_lset(&Q.Z, 1) == 0);

    mbedtls_ecp_set_max_ops((unsigned) max_ops);

    cnt_restarts = 0;
    do {
        ECP_PT_RESET(&R);
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
    } while (ret == MBEDTLS_ERR_ECP_IN_PROGRESS && ++cnt_restarts);

    TEST_ASSERT(ret == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xR) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yR) == 0);

    TEST_ASSERT(cnt_restarts >= min_restarts);
    TEST_ASSERT(cnt_restarts <= max_restarts);

    /* Do we leak memory when aborting an operation?
     * This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
```

## Call pattern 8

```c
* This test only makes sense when we actually restart */
    if (min_restarts > 0) {
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);
    mbedtls_mpi_free(&xR); mbedtls_mpi_free(&yR);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vect(int id, char *dA_str, char *xA_str, char *yA_str,
                   char *dB_str, char *xB_str, char *yB_str,
                   char *xZ_str, char *yZ_str)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&xB); mbedtls_mpi_init(&yB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
```

## Call pattern 9

```c
if (min_restarts > 0) {
        ret = mbedtls_ecp_muladd_restartable(&grp, &R,
                                             &u1, &grp.G, &u2, &Q, &ctx);
        TEST_ASSERT(ret == MBEDTLS_ERR_ECP_IN_PROGRESS);
    }

exit:
    mbedtls_ecp_restart_free(&ctx);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);
    mbedtls_mpi_free(&xR); mbedtls_mpi_free(&yR);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vect(int id, char *dA_str, char *xA_str, char *yA_str,
                   char *dB_str, char *xB_str, char *yB_str,
                   char *xZ_str, char *yZ_str)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&xB); mbedtls_mpi_init(&yB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_str) == 0);
```

## Call pattern 10

```c
/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vect(int id, char *dA_str, char *xA_str, char *yA_str,
                   char *dB_str, char *xB_str, char *yB_str,
                   char *xZ_str, char *yZ_str)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&xB); mbedtls_mpi_init(&yB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yB, yB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
```

## Call pattern 11

```c
/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vect(int id, char *dA_str, char *xA_str, char *yA_str,
                   char *dB_str, char *xB_str, char *yB_str,
                   char *xZ_str, char *yZ_str)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, yA, dB, xB, yB, xZ, yZ;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA); mbedtls_mpi_init(&yA); mbedtls_mpi_init(&dB);
    mbedtls_mpi_init(&xB); mbedtls_mpi_init(&yB); mbedtls_mpi_init(&xZ); mbedtls_mpi_init(&yZ);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yA, yA_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yB, yB_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xZ, xZ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&yZ, yZ_str) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yA) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
```

## Call pattern 12

```c
&mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yB) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA); mbedtls_mpi_free(&dB);
    mbedtls_mpi_free(&xB); mbedtls_mpi_free(&yB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vec_x(int id, char *dA_hex, char *xA_hex, char *dB_hex,
                    char *xB_hex, char *xS_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xB);
    mbedtls_mpi_init(&xS);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_hex) == 0);
```

## Call pattern 13

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yB) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xZ) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.Y, &yZ) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA); mbedtls_mpi_free(&yA); mbedtls_mpi_free(&dB);
    mbedtls_mpi_free(&xB); mbedtls_mpi_free(&yB); mbedtls_mpi_free(&xZ); mbedtls_mpi_free(&yZ);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vec_x(int id, char *dA_hex, char *xA_hex, char *dB_hex,
                    char *xB_hex, char *xS_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xB);
    mbedtls_mpi_init(&xS);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xS, xS_hex) == 0);
```

## Call pattern 14

```c
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vec_x(int id, char *dA_hex, char *xA_hex, char *dB_hex,
                    char *xB_hex, char *xS_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xB);
    mbedtls_mpi_init(&xS);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xS, xS_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
```

## Call pattern 15

```c
/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_vec_x(int id, char *dA_hex, char *xA_hex, char *dB_hex,
                    char *xB_hex, char *xS_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R;
    mbedtls_mpi dA, xA, dB, xB, xS;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&dA); mbedtls_mpi_init(&xA);
    mbedtls_mpi_init(&dB); mbedtls_mpi_init(&xB);
    mbedtls_mpi_init(&xS);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&dA, dA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&dB, dB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xA, xA_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xB, xB_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&xS, xS_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xA) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);
```

## Call pattern 16

```c
TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dB, &grp.G,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xB);
    mbedtls_mpi_free(&xS);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_mul(int id, data_t *n_hex,
                  data_t *Px_hex, data_t *Py_hex, data_t *Pz_hex,
                  data_t *nPx_hex, data_t *nPy_hex, data_t *nPz_hex,
                  int expected_ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&nP);
    mbedtls_mpi_init(&n);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&n, n_hex->x, n_hex->len) == 0);
```

## Call pattern 17

```c
&mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xB);
    mbedtls_mpi_free(&xS);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_mul(int id, data_t *n_hex,
                  data_t *Px_hex, data_t *Py_hex, data_t *Pz_hex,
                  data_t *nPx_hex, data_t *nPy_hex, data_t *nPz_hex,
                  int expected_ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&nP);
    mbedtls_mpi_init(&n);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&n, n_hex->x, n_hex->len) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&P.X, Px_hex->x, Px_hex->len) == 0);
```

## Call pattern 18

```c
TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xB) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &dA, &R,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &R) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&R.X, &xS) == 0);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&dA); mbedtls_mpi_free(&xA);
    mbedtls_mpi_free(&dB); mbedtls_mpi_free(&xB);
    mbedtls_mpi_free(&xS);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_mul(int id, data_t *n_hex,
                  data_t *Px_hex, data_t *Py_hex, data_t *Pz_hex,
                  data_t *nPx_hex, data_t *nPy_hex, data_t *nPz_hex,
                  int expected_ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&nP);
    mbedtls_mpi_init(&n);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&n, n_hex->x, n_hex->len) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&P.X, Px_hex->x, Px_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&P.Y, Py_hex->x, Py_hex->len) == 0);
```

## Call pattern 19

```c
void ecp_test_mul(int id, data_t *n_hex,
                  data_t *Px_hex, data_t *Py_hex, data_t *Pz_hex,
                  data_t *nPx_hex, data_t *nPy_hex, data_t *nPz_hex,
                  int expected_ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P, nP, R;
    mbedtls_mpi n;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P); mbedtls_ecp_point_init(&nP);
    mbedtls_mpi_init(&n);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&n, n_hex->x, n_hex->len) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&P.X, Px_hex->x, Px_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&P.Y, Py_hex->x, Py_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&P.Z, Pz_hex->x, Pz_hex->len) == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.X, nPx_hex->x, nPx_hex->len)
                == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.Y, nPy_hex->x, nPy_hex->len)
                == 0);
    TEST_ASSERT(mbedtls_mpi_read_binary(&nP.Z, nPz_hex->x, nPz_hex->len)
                == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &R, &n, &P,
                                &mbedtls_test_rnd_pseudo_rand, &rnd_info)
                == expected_ret);

    if (expected_ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.X, &R.X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Y, &R.Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Z, &R.Z) == 0);
    }
```

## Call pattern 20

```c
&mbedtls_test_rnd_pseudo_rand, &rnd_info)
                == expected_ret);

    if (expected_ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.X, &R.X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Y, &R.Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&nP.Z, &R.Z) == 0);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&nP);
    mbedtls_mpi_free(&n);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_mul_rng(int id, data_t *d_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&d, d_hex->x, d_hex->len) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                                &mbedtls_test_rnd_zero_rand, NULL)
                == MBEDTLS_ERR_ECP_RANDOM_FAILED);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
}
```

## Call pattern 21

```c
mbedtls_ecp_point_free(&P); mbedtls_ecp_point_free(&nP);
    mbedtls_mpi_free(&n);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void ecp_test_mul_rng(int id, data_t *d_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;

    mbedtls_ecp_group_init(&grp); mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&d, d_hex->x, d_hex->len) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                                &mbedtls_test_rnd_zero_rand, NULL)
                == MBEDTLS_ERR_ECP_RANDOM_FAILED);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED:MBEDTLS_ECP_C */
void ecp_muladd(int id,
                data_t *u1_bin, data_t *P1_bin,
                data_t *u2_bin, data_t *P2_bin,
                data_t *expected_result)
{
    /* Compute R = u1 * P1 + u2 * P2 */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P1, P2, R;
```

## Call pattern 22

```c
TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &grp.G) == 0);

    TEST_ASSERT(mbedtls_mpi_read_binary(&d, d_hex->x, d_hex->len) == 0);

    TEST_ASSERT(mbedtls_ecp_mul(&grp, &Q, &d, &grp.G,
                                &mbedtls_test_rnd_zero_rand, NULL)
                == MBEDTLS_ERR_ECP_RANDOM_FAILED);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED:MBEDTLS_ECP_C */
void ecp_muladd(int id,
                data_t *u1_bin, data_t *P1_bin,
                data_t *u2_bin, data_t *P2_bin,
                data_t *expected_result)
{
    /* Compute R = u1 * P1 + u2 * P2 */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P1, P2, R;
    mbedtls_mpi u1, u2;
    uint8_t actual_result[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&P2);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u2);

    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, id));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u1, u1_bin->x, u1_bin->len));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u2, u2_bin->x, u2_bin->len));
```

## Call pattern 23

```c
{
    /* Compute R = u1 * P1 + u2 * P2 */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P1, P2, R;
    mbedtls_mpi u1, u2;
    uint8_t actual_result[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&P2);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u2);

    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, id));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u1, u1_bin->x, u1_bin->len));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u2, u2_bin->x, u2_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P1,
                                                P1_bin->x, P1_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P2,
                                                P2_bin->x, P2_bin->len));

    TEST_EQUAL(0, mbedtls_ecp_muladd(&grp, &R, &u1, &P1, &u2, &P2));
    TEST_EQUAL(0, mbedtls_ecp_point_write_binary(
                   &grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED,
                   &len, actual_result, sizeof(actual_result)));
    TEST_ASSERT(len <= MBEDTLS_ECP_MAX_PT_LEN);

    TEST_MEMORY_COMPARE(expected_result->x, expected_result->len,
                        actual_result, len);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P1);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}
```

## Call pattern 24

```c
/* Compute R = u1 * P1 + u2 * P2 */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P1, P2, R;
    mbedtls_mpi u1, u2;
    uint8_t actual_result[MBEDTLS_ECP_MAX_PT_LEN];
    size_t len;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&P2);
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u2);

    TEST_EQUAL(0, mbedtls_ecp_group_load(&grp, id));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u1, u1_bin->x, u1_bin->len));
    TEST_EQUAL(0, mbedtls_mpi_read_binary(&u2, u2_bin->x, u2_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P1,
                                                P1_bin->x, P1_bin->len));
    TEST_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &P2,
                                                P2_bin->x, P2_bin->len));

    TEST_EQUAL(0, mbedtls_ecp_muladd(&grp, &R, &u1, &P1, &u2, &P2));
    TEST_EQUAL(0, mbedtls_ecp_point_write_binary(
                   &grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED,
                   &len, actual_result, sizeof(actual_result)));
    TEST_ASSERT(len <= MBEDTLS_ECP_MAX_PT_LEN);

    TEST_MEMORY_COMPARE(expected_result->x, expected_result->len,
                        actual_result, len);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P1);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}
/* END_CASE */
```

## Call pattern 25

```c
&grp, &R, MBEDTLS_ECP_PF_UNCOMPRESSED,
                   &len, actual_result, sizeof(actual_result)));
    TEST_ASSERT(len <= MBEDTLS_ECP_MAX_PT_LEN);

    TEST_MEMORY_COMPARE(expected_result->x, expected_result->len,
                        actual_result, len);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P1);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_fast_mod(int id, char *N_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi N, R;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&R);
    mbedtls_ecp_group_init(&grp);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, N_str) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(grp.modp != NULL);

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&R, &N, &grp.P) == 0);

    TEST_ASSERT(grp.modp(&N) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&N) <= grp.pbits + 3);

    /*
     * Use mod rather than addition/subtraction in case previous test fails
```

## Call pattern 26

```c
&len, actual_result, sizeof(actual_result)));
    TEST_ASSERT(len <= MBEDTLS_ECP_MAX_PT_LEN);

    TEST_MEMORY_COMPARE(expected_result->x, expected_result->len,
                        actual_result, len);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&P1);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_fast_mod(int id, char *N_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi N, R;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&R);
    mbedtls_ecp_group_init(&grp);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, N_str) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(grp.modp != NULL);

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&R, &N, &grp.P) == 0);

    TEST_ASSERT(grp.modp(&N) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&N) <= grp.pbits + 3);

    /*
     * Use mod rather than addition/subtraction in case previous test fails
     */
```

## Call pattern 27

```c
mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_fast_mod(int id, char *N_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi N, R;

    mbedtls_mpi_init(&N); mbedtls_mpi_init(&R);
    mbedtls_ecp_group_init(&grp);

    TEST_ASSERT(mbedtls_test_read_mpi(&N, N_str) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(grp.modp != NULL);

    /*
     * Store correct result before we touch N
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&R, &N, &grp.P) == 0);

    TEST_ASSERT(grp.modp(&N) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&N) <= grp.pbits + 3);

    /*
     * Use mod rather than addition/subtraction in case previous test fails
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&N, &N, &grp.P) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&N, &R) == 0);

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&R);
    mbedtls_ecp_group_free(&grp);
}
/* END_CASE */

/* BEGIN_CASE */
```

## Call pattern 28

```c
TEST_ASSERT(mbedtls_mpi_mod_mpi(&R, &N, &grp.P) == 0);

    TEST_ASSERT(grp.modp(&N) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&N) <= grp.pbits + 3);

    /*
     * Use mod rather than addition/subtraction in case previous test fails
     */
    TEST_ASSERT(mbedtls_mpi_mod_mpi(&N, &N, &grp.P) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&N, &R) == 0);

exit:
    mbedtls_mpi_free(&N); mbedtls_mpi_free(&R);
    mbedtls_ecp_group_free(&grp);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_write_binary(int id, char *x, char *y, char *z, int format,
                      data_t *out, int blen, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_ecp_keypair key;
    unsigned char buf[256];
    size_t olen;

    memset(buf, 0, sizeof(buf));

    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_ecp_keypair_init(&key);

    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    TEST_EQUAL(mbedtls_test_read_mpi(&P.X, x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&P.Y, y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&P.Z, z), 0);

    TEST_EQUAL(mbedtls_ecp_point_write_binary(&grp, &P, format,
                                              &olen, buf, blen), ret);
```

## Call pattern 29

```c
/* END_CASE */

/* BEGIN_CASE */
void ecp_read_binary(int id, data_t *buf, char *x, char *y, char *z,
                     int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, x) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Z, z) == 0);

    TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        if (mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Y, 0) == 0);
            TEST_ASSERT(P.Y.p == NULL);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Z, 1) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&P.Z, 1) == 0);
        } else {
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);

            if (buf->x[0] == 0x04) {
                /* re-encode in compressed format and test read again */
                mbedtls_mpi_free(&P.Y);
                buf->x[0] = 0x02 + mbedtls_mpi_get_bit(&Y, 0);
                TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len/2+1) == 0);
                TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            }
```

## Call pattern 30

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        if (mbedtls_ecp_get_type(&grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Y, 0) == 0);
            TEST_ASSERT(P.Y.p == NULL);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&Z, 1) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_int(&P.Z, 1) == 0);
        } else {
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);

            if (buf->x[0] == 0x04) {
                /* re-encode in compressed format and test read again */
                mbedtls_mpi_free(&P.Y);
                buf->x[0] = 0x02 + mbedtls_mpi_get_bit(&Y, 0);
                TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len/2+1) == 0);
                TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            }
        }
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_tls_read_point(int id, data_t *buf, char *x, char *y,
                                char *z, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;
    const unsigned char *vbuf = buf->x;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
```

## Call pattern 31

```c
if (buf->x[0] == 0x04) {
                /* re-encode in compressed format and test read again */
                mbedtls_mpi_free(&P.Y);
                buf->x[0] = 0x02 + mbedtls_mpi_get_bit(&Y, 0);
                TEST_ASSERT(mbedtls_ecp_point_read_binary(&grp, &P, buf->x, buf->len/2+1) == 0);
                TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
            }
        }
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_tls_read_point(int id, data_t *buf, char *x, char *y,
                                char *z, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;
    const unsigned char *vbuf = buf->x;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, x) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Z, z) == 0);

    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &P, &vbuf, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
```

## Call pattern 32

```c
/* BEGIN_CASE */
void mbedtls_ecp_tls_read_point(int id, data_t *buf, char *x, char *y,
                                char *z, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi X, Y, Z;
    const unsigned char *vbuf = buf->x;


    mbedtls_ecp_group_init(&grp); mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, x) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Z, z) == 0);

    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &P, &vbuf, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);
        TEST_ASSERT((uint32_t) (vbuf - buf->x) == buf->len);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_tls_write_read_point(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
```

## Call pattern 33

```c
TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &P, &vbuf, buf->len) == ret);

    if (ret == 0) {
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.X, &X) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Y, &Y) == 0);
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&P.Z, &Z) == 0);
        TEST_ASSERT((uint32_t) (vbuf - buf->x) == buf->len);
    }

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_tls_write_read_point(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt;
    unsigned char buf[256];
    const unsigned char *vbuf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pt);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
    TEST_ASSERT(mbedtls_ecp_tls_write_point(&grp, &grp.G,
                                            MBEDTLS_ECP_PF_COMPRESSED, &olen, buf, 256) == 0);
    TEST_ASSERT(mbedtls_ecp_tls_read_point(&grp, &pt, &vbuf, olen) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.X, &pt.X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Y, &pt.Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.G.Z, &pt.Z) == 0);
    TEST_ASSERT(vbuf == buf + olen);

    memset(buf, 0x00, sizeof(buf)); vbuf = buf;
```

## Call pattern 34

```c
const mbedtls_ecp_curve_info *crv, *crv_tls_id, *crv_name;

    mbedtls_mpi exp_P, exp_A, exp_B, exp_G_x, exp_G_y, exp_N;

    unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
```

## Call pattern 35

```c
mbedtls_mpi exp_P, exp_A, exp_B, exp_G_x, exp_G_y, exp_N;

    unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
```

## Call pattern 36

```c
mbedtls_mpi exp_P, exp_A, exp_B, exp_G_x, exp_G_y, exp_N;

    unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_A, &grp.A), 0);
```

## Call pattern 37

```c
unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_A, &grp.A), 0);
    }
```

## Call pattern 38

```c
unsigned char buf[3], ecparameters[3] = { 3, 0, tls_id };
    const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_A, &grp.A), 0);
    }
    if (*B != 0) {
```

## Call pattern 39

```c
const unsigned char *vbuf = buf;
    size_t olen;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_init(&grp_read);
    mbedtls_ecp_group_init(&grp_cpy);

    mbedtls_mpi_init(&exp_P);
    mbedtls_mpi_init(&exp_A);
    mbedtls_mpi_init(&exp_B);
    mbedtls_mpi_init(&exp_G_x);
    mbedtls_mpi_init(&exp_G_y);
    mbedtls_mpi_init(&exp_N);

    // Read expected parameters
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_P, P), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_A, A), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_x, G_x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_N, N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_B, B), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&exp_G_y, G_y), 0);

    // Convert exp_A to internal representation (A+2)/4
    if (crv_type == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        TEST_EQUAL(mbedtls_mpi_add_int(&exp_A, &exp_A, 2), 0);
        TEST_EQUAL(mbedtls_mpi_div_int(&exp_A, NULL, &exp_A, 4), 0);
    }

    // Load group
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);

    // Compare group with expected parameters
    // A is NULL for SECPxxxR1 curves
    // B and G_y are NULL for curve25519 and curve448
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_P, &grp.P), 0);
    if (*A != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_A, &grp.A), 0);
    }
    if (*B != 0) {
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&exp_B, &grp.B), 0);
```

## Call pattern 40

```c
}
    TEST_EQUAL(crv->grp_id, id);
    for (g_id = mbedtls_ecp_grp_id_list();
         *g_id != MBEDTLS_ECP_DP_NONE && *g_id != (unsigned) id;
         g_id++) {
        ;
    }
    TEST_EQUAL(*g_id, (unsigned) id);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_group_free(&grp_cpy);
    mbedtls_ecp_group_free(&grp_read);
    mbedtls_mpi_free(&exp_P); mbedtls_mpi_free(&exp_A);
    mbedtls_mpi_free(&exp_B); mbedtls_mpi_free(&exp_G_x);
    mbedtls_mpi_free(&exp_G_y); mbedtls_mpi_free(&exp_N);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_check_privkey(int id, char *key_hex, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
```

## Call pattern 41

```c
TEST_EQUAL(crv->grp_id, id);
    for (g_id = mbedtls_ecp_grp_id_list();
         *g_id != MBEDTLS_ECP_DP_NONE && *g_id != (unsigned) id;
         g_id++) {
        ;
    }
    TEST_EQUAL(*g_id, (unsigned) id);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_group_free(&grp_cpy);
    mbedtls_ecp_group_free(&grp_read);
    mbedtls_mpi_free(&exp_P); mbedtls_mpi_free(&exp_A);
    mbedtls_mpi_free(&exp_B); mbedtls_mpi_free(&exp_G_x);
    mbedtls_mpi_free(&exp_G_y); mbedtls_mpi_free(&exp_N);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_check_privkey(int id, char *key_hex, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
                                int id, char *d, char *Qx, char *Qy,
```

## Call pattern 42

```c
for (g_id = mbedtls_ecp_grp_id_list();
         *g_id != MBEDTLS_ECP_DP_NONE && *g_id != (unsigned) id;
         g_id++) {
        ;
    }
    TEST_EQUAL(*g_id, (unsigned) id);

exit:
    mbedtls_ecp_group_free(&grp); mbedtls_ecp_group_free(&grp_cpy);
    mbedtls_ecp_group_free(&grp_read);
    mbedtls_mpi_free(&exp_P); mbedtls_mpi_free(&exp_A);
    mbedtls_mpi_free(&exp_B); mbedtls_mpi_free(&exp_G_x);
    mbedtls_mpi_free(&exp_G_y); mbedtls_mpi_free(&exp_N);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_check_privkey(int id, char *key_hex, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
                                int id, char *d, char *Qx, char *Qy,
                                int ret)
```

## Call pattern 43

```c
mbedtls_mpi_free(&exp_B); mbedtls_mpi_free(&exp_G_x);
    mbedtls_mpi_free(&exp_G_y); mbedtls_mpi_free(&exp_N);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_check_privkey(int id, char *key_hex, int ret)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
                                int id, char *d, char *Qx, char *Qy,
                                int ret)
{
    mbedtls_ecp_keypair pub, prv;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&pub);
    mbedtls_ecp_keypair_init(&prv);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    if (id_pub != MBEDTLS_ECP_DP_NONE) {
        TEST_ASSERT(mbedtls_ecp_group_load(&pub.grp, id_pub) == 0);
    }
```

## Call pattern 44

```c
mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, key_hex) == 0);

    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == ret);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_check_pub_priv(int id_pub, char *Qx_pub, char *Qy_pub,
                                int id, char *d, char *Qx, char *Qy,
                                int ret)
{
    mbedtls_ecp_keypair pub, prv;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&pub);
    mbedtls_ecp_keypair_init(&prv);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    if (id_pub != MBEDTLS_ECP_DP_NONE) {
        TEST_ASSERT(mbedtls_ecp_group_load(&pub.grp, id_pub) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&pub.Q, 16, Qx_pub, Qy_pub) == 0);

    if (id != MBEDTLS_ECP_DP_NONE) {
        TEST_ASSERT(mbedtls_ecp_group_load(&prv.grp, id) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&prv.Q, 16, Qx, Qy) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&prv.d, d) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pub_priv(&pub, &prv,
```

## Call pattern 45

```c
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_gen_keypair(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &Q) == 0);
    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_gen_key(int id)
{
    mbedtls_ecp_keypair key;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&key);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
```

## Call pattern 46

```c
TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);

    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&grp, &Q) == 0);
    TEST_ASSERT(mbedtls_ecp_check_privkey(&grp, &d) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECP_C */
void mbedtls_ecp_gen_key(int id)
{
    mbedtls_ecp_keypair key;
    mbedtls_test_rnd_pseudo_info rnd_info;

    mbedtls_ecp_keypair_init(&key);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));

    TEST_ASSERT(mbedtls_ecp_gen_key(id, &key,
                                    &mbedtls_test_rnd_pseudo_rand,
                                    &rnd_info) == 0);

    TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), id);
    TEST_ASSERT(mbedtls_ecp_check_pubkey(&key.grp, &key.Q) == 0);
    TEST_ASSERT(mbedtls_ecp_check_privkey(&key.grp, &key.d) == 0);

exit:
    mbedtls_ecp_keypair_free(&key);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_set_public_key_group_check(int grp_id, int expected_ret)
```

## Call pattern 47

```c
/* BEGIN_CASE */
void ecp_set_public_key_after_private(int private_grp_id, data_t *private_data,
                                      int public_grp_id, data_t *public_data)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);

    TEST_EQUAL(mbedtls_ecp_group_load(&grp, public_grp_id), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &Q,
                                             public_data->x, public_data->len),
               0);
    TEST_EQUAL(mbedtls_ecp_read_key(private_grp_id, &key,
                                    private_data->x, private_data->len),
               0);
    TEST_EQUAL(mbedtls_mpi_copy(&d, &key.d), 0);

    int ret = mbedtls_ecp_set_public_key(public_grp_id, &key, &Q);

    if (private_grp_id == public_grp_id) {
        TEST_EQUAL(ret, 0);
        TEST_EQUAL(key.grp.id, public_grp_id);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &Q), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&d, &key.d), 0);
    } else {
        TEST_EQUAL(ret, MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}
```

## Call pattern 48

```c
TEST_EQUAL(ret, 0);
        TEST_EQUAL(key.grp.id, public_grp_id);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &Q), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&d, &key.d), 0);
    } else {
        TEST_EQUAL(ret, MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_read_key(int grp_id, data_t *in_key, int expected, int canonical)
{
    int ret = 0;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_keypair key2;
    mbedtls_ecp_keypair_init(&key2);

    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Y, 2), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Z, 3), 0);

    ret = mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len);
    TEST_ASSERT(ret == expected);

    if (expected == 0) {
        TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), grp_id);
        ret = mbedtls_ecp_check_privkey(&key.grp, &key.d);
        TEST_ASSERT(ret == 0);

        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.X, 1), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Y, 2), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Z, 3), 0);
```

## Call pattern 49

```c
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_read_key(int grp_id, data_t *in_key, int expected, int canonical)
{
    int ret = 0;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_keypair key2;
    mbedtls_ecp_keypair_init(&key2);

    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Y, 2), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Z, 3), 0);

    ret = mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len);
    TEST_ASSERT(ret == expected);

    if (expected == 0) {
        TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), grp_id);
        ret = mbedtls_ecp_check_privkey(&key.grp, &key.d);
        TEST_ASSERT(ret == 0);

        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.X, 1), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Y, 2), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Z, 3), 0);

        if (canonical && in_key->len == (key.grp.nbits + 7) / 8) {
            unsigned char buf[MBEDTLS_ECP_MAX_BYTES];
            size_t length = 0xdeadbeef;

            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key,
                                                 &length, buf, in_key->len), 0);
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                buf, length);

        } else {
            unsigned char export1[MBEDTLS_ECP_MAX_BYTES];
            unsigned char export2[MBEDTLS_ECP_MAX_BYTES];
```

## Call pattern 50

```c
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_ecp_read_key(int grp_id, data_t *in_key, int expected, int canonical)
{
    int ret = 0;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_keypair key2;
    mbedtls_ecp_keypair_init(&key2);

    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Y, 2), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Z, 3), 0);

    ret = mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len);
    TEST_ASSERT(ret == expected);

    if (expected == 0) {
        TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), grp_id);
        ret = mbedtls_ecp_check_privkey(&key.grp, &key.d);
        TEST_ASSERT(ret == 0);

        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.X, 1), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Y, 2), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Z, 3), 0);

        if (canonical && in_key->len == (key.grp.nbits + 7) / 8) {
            unsigned char buf[MBEDTLS_ECP_MAX_BYTES];
            size_t length = 0xdeadbeef;

            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key,
                                                 &length, buf, in_key->len), 0);
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                buf, length);

        } else {
            unsigned char export1[MBEDTLS_ECP_MAX_BYTES];
            unsigned char export2[MBEDTLS_ECP_MAX_BYTES];
```

## Call pattern 51

```c
/* BEGIN_CASE */
void mbedtls_ecp_read_key(int grp_id, data_t *in_key, int expected, int canonical)
{
    int ret = 0;
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    mbedtls_ecp_keypair key2;
    mbedtls_ecp_keypair_init(&key2);

    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.X, 1), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Y, 2), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&key.Q.Z, 3), 0);

    ret = mbedtls_ecp_read_key(grp_id, &key, in_key->x, in_key->len);
    TEST_ASSERT(ret == expected);

    if (expected == 0) {
        TEST_EQUAL(mbedtls_ecp_keypair_get_group_id(&key), grp_id);
        ret = mbedtls_ecp_check_privkey(&key.grp, &key.d);
        TEST_ASSERT(ret == 0);

        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.X, 1), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Y, 2), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_int(&key.Q.Z, 3), 0);

        if (canonical && in_key->len == (key.grp.nbits + 7) / 8) {
            unsigned char buf[MBEDTLS_ECP_MAX_BYTES];
            size_t length = 0xdeadbeef;

            TEST_EQUAL(mbedtls_ecp_write_key_ext(&key,
                                                 &length, buf, in_key->len), 0);
            TEST_MEMORY_COMPARE(in_key->x, in_key->len,
                                buf, length);

        } else {
            unsigned char export1[MBEDTLS_ECP_MAX_BYTES];
            unsigned char export2[MBEDTLS_ECP_MAX_BYTES];

            size_t length1 = 0xdeadbeef;
```

## Call pattern 52

```c
mbedtls_free(exported);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS:MBEDTLS_ECP_MONTGOMERY_ENABLED:MBEDTLS_ECP_LIGHT */
void genkey_mx_known_answer(int bits, data_t *seed, data_t *expected)
{
    mbedtls_test_rnd_buf_info rnd_info;
    mbedtls_mpi d;
    int ret;
    uint8_t *actual = NULL;

    mbedtls_mpi_init(&d);
    rnd_info.buf = seed->x;
    rnd_info.length = seed->len;
    rnd_info.fallback_f_rng = NULL;
    rnd_info.fallback_p_rng = NULL;

    TEST_CALLOC(actual, expected->len);

    ret = mbedtls_ecp_gen_privkey_mx(bits, &d,
                                     mbedtls_test_rnd_buffer_rand, &rnd_info);

    if (expected->len == 0) {
        /* Expecting an error (happens if there isn't enough randomness) */
        TEST_ASSERT(ret != 0);
    } else {
        TEST_EQUAL(ret, 0);
        TEST_EQUAL((size_t) bits + 1, mbedtls_mpi_bitlen(&d));
        TEST_EQUAL(0, mbedtls_mpi_write_binary(&d, actual, expected->len));
        /* Test the exact result. This assumes that the output of the
         * RNG is used in a specific way, which is overly constraining.
         * The advantage is that it's easier to test the expected properties
         * of the generated key:
         * - The most significant bit must be at a specific positions
         *   (can be enforced by checking the bit-length).
         * - The least significant bits must have specific values
         *   (can be enforced by checking these bits).
         * - Other bits must be random (by testing with different RNG outputs,
         *   we validate that those bits are indeed influenced by the RNG). */
```

## Call pattern 53

```c
TEST_CALLOC(actual, expected->len);

    ret = mbedtls_ecp_gen_privkey_mx(bits, &d,
                                     mbedtls_test_rnd_buffer_rand, &rnd_info);

    if (expected->len == 0) {
        /* Expecting an error (happens if there isn't enough randomness) */
        TEST_ASSERT(ret != 0);
    } else {
        TEST_EQUAL(ret, 0);
        TEST_EQUAL((size_t) bits + 1, mbedtls_mpi_bitlen(&d));
        TEST_EQUAL(0, mbedtls_mpi_write_binary(&d, actual, expected->len));
        /* Test the exact result. This assumes that the output of the
         * RNG is used in a specific way, which is overly constraining.
         * The advantage is that it's easier to test the expected properties
         * of the generated key:
         * - The most significant bit must be at a specific positions
         *   (can be enforced by checking the bit-length).
         * - The least significant bits must have specific values
         *   (can be enforced by checking these bits).
         * - Other bits must be random (by testing with different RNG outputs,
         *   we validate that those bits are indeed influenced by the RNG). */
        TEST_MEMORY_COMPARE(expected->x, expected->len,
                            actual, expected->len);
    }

exit:
    mbedtls_free(actual);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_set_zero(int id, data_t *P_bin)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt, zero_pt, nonzero_pt;

    mbedtls_ecp_group_init(&grp);
```

## Call pattern 54

```c
* - The most significant bit must be at a specific positions
         *   (can be enforced by checking the bit-length).
         * - The least significant bits must have specific values
         *   (can be enforced by checking these bits).
         * - Other bits must be random (by testing with different RNG outputs,
         *   we validate that those bits are indeed influenced by the RNG). */
        TEST_MEMORY_COMPARE(expected->x, expected->len,
                            actual, expected->len);
    }

exit:
    mbedtls_free(actual);
    mbedtls_mpi_free(&d);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_set_zero(int id, data_t *P_bin)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point pt, zero_pt, nonzero_pt;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&pt);
    mbedtls_ecp_point_init(&zero_pt);
    mbedtls_ecp_point_init(&nonzero_pt);

    // Set zero and non-zero points for comparison
    TEST_EQUAL(mbedtls_ecp_set_zero(&zero_pt), 0);
    TEST_EQUAL(mbedtls_ecp_group_load(&grp, id), 0);
    TEST_EQUAL(mbedtls_ecp_point_read_binary(&grp, &nonzero_pt,
                                             P_bin->x, P_bin->len), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&zero_pt), 1);
    TEST_EQUAL(mbedtls_ecp_is_zero(&nonzero_pt), 0);

    // Test initialized point
    TEST_EQUAL(mbedtls_ecp_set_zero(&pt), 0);
    TEST_EQUAL(mbedtls_ecp_is_zero(&pt), 1);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&zero_pt, &pt), 0);
    TEST_EQUAL(mbedtls_ecp_point_cmp(&nonzero_pt, &zero_pt),
```

## Call pattern 55

```c
/* END_CASE */

/* BEGIN_CASE */
void ecp_export(int id, char *Qx, char *Qy, char *d, int expected_ret, int invalid_grp)
{
    mbedtls_ecp_keypair key;
    mbedtls_ecp_group export_grp;
    mbedtls_mpi export_d;
    mbedtls_ecp_point export_Q;

    mbedtls_ecp_group_init(&export_grp);
    mbedtls_ecp_group_init(&key.grp);
    mbedtls_mpi_init(&export_d);
    mbedtls_ecp_point_init(&export_Q);

    mbedtls_ecp_keypair_init(&key);
    if (invalid_grp == 0) {
        TEST_ASSERT(mbedtls_ecp_group_load(&key.grp, id) == 0);
    }
    TEST_ASSERT(mbedtls_ecp_point_read_string(&key.Q, 16, Qx, Qy) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&key.d, d) == 0);

    TEST_EQUAL(mbedtls_ecp_export(&key, &export_grp,
                                  &export_d, &export_Q), expected_ret);

    if (expected_ret == 0) {
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &export_Q), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&key.d, &export_d), 0);
        TEST_EQUAL(mbedtls_ecp_group_cmp(&key.grp, &export_grp), 0);

        /* Check consistency with the group id */
        TEST_EQUAL(export_grp.id,
                   mbedtls_ecp_keypair_get_group_id(&key));

        /* Test null arguments: grp only */
        mbedtls_ecp_group_free(&export_grp);
        mbedtls_ecp_group_init(&export_grp);
        TEST_EQUAL(mbedtls_ecp_export(&key, &export_grp, NULL, NULL), 0);
        TEST_EQUAL(mbedtls_ecp_group_cmp(&key.grp, &export_grp), 0);
```

## Call pattern 56

```c
/* Check consistency with the group id */
        TEST_EQUAL(export_grp.id,
                   mbedtls_ecp_keypair_get_group_id(&key));

        /* Test null arguments: grp only */
        mbedtls_ecp_group_free(&export_grp);
        mbedtls_ecp_group_init(&export_grp);
        TEST_EQUAL(mbedtls_ecp_export(&key, &export_grp, NULL, NULL), 0);
        TEST_EQUAL(mbedtls_ecp_group_cmp(&key.grp, &export_grp), 0);

        /* Test null arguments: d only */
        mbedtls_mpi_free(&export_d);
        mbedtls_mpi_init(&export_d);
        TEST_EQUAL(mbedtls_ecp_export(&key, NULL, &export_d, NULL), 0);
        TEST_EQUAL(mbedtls_mpi_cmp_mpi(&key.d, &export_d), 0);

        /* Test null arguments: Q only */
        mbedtls_ecp_point_free(&export_Q);
        mbedtls_ecp_point_init(&export_Q);
        TEST_EQUAL(mbedtls_ecp_export(&key, NULL, NULL, &export_Q), 0);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &export_Q), 0);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&export_grp);
    mbedtls_mpi_free(&export_d);
    mbedtls_ecp_point_free(&export_Q);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_check_order(int id, char *expected_order_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi expected_n;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&expected_n);
```

## Call pattern 57

```c
TEST_EQUAL(mbedtls_mpi_cmp_mpi(&key.d, &export_d), 0);

        /* Test null arguments: Q only */
        mbedtls_ecp_point_free(&export_Q);
        mbedtls_ecp_point_init(&export_Q);
        TEST_EQUAL(mbedtls_ecp_export(&key, NULL, NULL, &export_Q), 0);
        TEST_EQUAL(mbedtls_ecp_point_cmp(&key.Q, &export_Q), 0);
    }

exit:
    mbedtls_ecp_keypair_free(&key);
    mbedtls_ecp_group_free(&export_grp);
    mbedtls_mpi_free(&export_d);
    mbedtls_ecp_point_free(&export_Q);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_check_order(int id, char *expected_order_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi expected_n;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&expected_n);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&expected_n, expected_order_hex) == 0);

    // check sign bits are well-formed (i.e. 1 or -1) - see #5810
    TEST_ASSERT(grp.N.s == -1 || grp.N.s == 1);
    TEST_ASSERT(expected_n.s == -1 || expected_n.s == 1);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.N, &expected_n) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&expected_n);
}
/* END_CASE */
```

## Call pattern 58

```c
mbedtls_mpi_free(&export_d);
    mbedtls_ecp_point_free(&export_Q);
}
/* END_CASE */

/* BEGIN_CASE */
void ecp_check_order(int id, char *expected_order_hex)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi expected_n;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&expected_n);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&expected_n, expected_order_hex) == 0);

    // check sign bits are well-formed (i.e. 1 or -1) - see #5810
    TEST_ASSERT(grp.N.s == -1 || grp.N.s == 1);
    TEST_ASSERT(expected_n.s == -1 || expected_n.s == 1);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.N, &expected_n) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&expected_n);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS:MBEDTLS_ECP_WITH_MPI_UINT */
void ecp_mod_p_generic_raw(int curve_id,
                           char *input_N,
                           char *input_X,
                           char *result)
{
    mbedtls_mpi_uint *X = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *res = NULL;
    size_t limbs_X;
    size_t limbs_N;
```

## Call pattern 59

```c
TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&expected_n, expected_order_hex) == 0);

    // check sign bits are well-formed (i.e. 1 or -1) - see #5810
    TEST_ASSERT(grp.N.s == -1 || grp.N.s == 1);
    TEST_ASSERT(expected_n.s == -1 || expected_n.s == 1);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&grp.N, &expected_n) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&expected_n);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_TEST_HOOKS:MBEDTLS_ECP_WITH_MPI_UINT */
void ecp_mod_p_generic_raw(int curve_id,
                           char *input_N,
                           char *input_X,
                           char *result)
{
    mbedtls_mpi_uint *X = NULL;
    mbedtls_mpi_uint *N = NULL;
    mbedtls_mpi_uint *res = NULL;
    size_t limbs_X;
    size_t limbs_N;
    size_t limbs_res;

    size_t bytes;
    size_t limbs;
    size_t curve_bits;
    int (*curve_func)(mbedtls_mpi_uint *X, size_t X_limbs);

    mbedtls_mpi_mod_modulus m;
    mbedtls_mpi_mod_modulus_init(&m);

    TEST_EQUAL(mbedtls_test_read_mpi_core(&X,   &limbs_X,   input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi_core(&N,   &limbs_N,   input_N), 0);
    TEST_EQUAL(mbedtls_test_read_mpi_core(&res, &limbs_res, result),  0);
```

