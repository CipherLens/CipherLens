# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_ecdsa.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
/* BEGIN_CASE */
void ecdsa_prim_zero(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char buf[MBEDTLS_MD_MAX_SIZE];

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(buf, 0, sizeof(buf));

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &Q, &r, &s) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_prim_random(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    mbedtls_test_rnd_pseudo_info rnd_info;
```

## Call pattern 2

```c
TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &Q, &r, &s) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_prim_random(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char buf[MBEDTLS_MD_MAX_SIZE];

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(buf, 0, sizeof(buf));

    /* prepare material for signature */
    TEST_ASSERT(mbedtls_test_rnd_pseudo_rand(&rnd_info,
                                             buf, sizeof(buf)) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
```

## Call pattern 3

```c
/* BEGIN_CASE */
void ecdsa_prim_random(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char buf[MBEDTLS_MD_MAX_SIZE];

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(buf, 0, sizeof(buf));

    /* prepare material for signature */
    TEST_ASSERT(mbedtls_test_rnd_pseudo_rand(&rnd_info,
                                             buf, sizeof(buf)) == 0);
    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &Q, &r, &s) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_prim_test_vectors(int id, char *d_str, char *xQ_str,
                             char *yQ_str, data_t *rnd_buf,
                             data_t *hash, char *r_str, char *s_str,
```

## Call pattern 4

```c
TEST_ASSERT(mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                        &mbedtls_test_rnd_pseudo_rand,
                                        &rnd_info) == 0);

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                                   &mbedtls_test_rnd_pseudo_rand,
                                   &rnd_info) == 0);
    TEST_ASSERT(mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &Q, &r, &s) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_prim_test_vectors(int id, char *d_str, char *xQ_str,
                             char *yQ_str, data_t *rnd_buf,
                             data_t *hash, char *r_str, char *s_str,
                             int result)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s, r_check, s_check, zero;
    mbedtls_test_rnd_buf_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);
    mbedtls_mpi_init(&zero);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_string(&Q, 16, xQ_str, yQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);
    rnd_info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    rnd_info.fallback_p_rng = NULL;
```

## Call pattern 5

```c
void ecdsa_prim_test_vectors(int id, char *d_str, char *xQ_str,
                             char *yQ_str, data_t *rnd_buf,
                             data_t *hash, char *r_str, char *s_str,
                             int result)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s, r_check, s_check, zero;
    mbedtls_test_rnd_buf_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);
    mbedtls_mpi_init(&zero);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_string(&Q, 16, xQ_str, yQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);
    rnd_info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    rnd_info.fallback_p_rng = NULL;
    rnd_info.buf = rnd_buf->x;
    rnd_info.length = rnd_buf->len;

    /* Fix rnd_buf->x by shifting it left if necessary */
    if (grp.nbits % 8 != 0) {
        unsigned char shift = 8 - (grp.nbits % 8);
        size_t i;

        for (i = 0; i < rnd_info.length - 1; i++) {
            rnd_buf->x[i] = rnd_buf->x[i] << shift | rnd_buf->x[i+1] >> (8 - shift);
        }

        rnd_buf->x[rnd_info.length-1] <<= shift;
    }

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash->x, hash->len,
                                   mbedtls_test_rnd_buffer_rand, &rnd_info) == result);
```

## Call pattern 6

```c
char *yQ_str, data_t *rnd_buf,
                             data_t *hash, char *r_str, char *s_str,
                             int result)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s, r_check, s_check, zero;
    mbedtls_test_rnd_buf_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);
    mbedtls_mpi_init(&zero);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_string(&Q, 16, xQ_str, yQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);
    rnd_info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    rnd_info.fallback_p_rng = NULL;
    rnd_info.buf = rnd_buf->x;
    rnd_info.length = rnd_buf->len;

    /* Fix rnd_buf->x by shifting it left if necessary */
    if (grp.nbits % 8 != 0) {
        unsigned char shift = 8 - (grp.nbits % 8);
        size_t i;

        for (i = 0; i < rnd_info.length - 1; i++) {
            rnd_buf->x[i] = rnd_buf->x[i] << shift | rnd_buf->x[i+1] >> (8 - shift);
        }

        rnd_buf->x[rnd_info.length-1] <<= shift;
    }

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash->x, hash->len,
                                   mbedtls_test_rnd_buffer_rand, &rnd_info) == result);
```

## Call pattern 7

```c
data_t *hash, char *r_str, char *s_str,
                             int result)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s, r_check, s_check, zero;
    mbedtls_test_rnd_buf_info rnd_info;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);
    mbedtls_mpi_init(&zero);

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_ecp_point_read_string(&Q, 16, xQ_str, yQ_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);
    rnd_info.fallback_f_rng = mbedtls_test_rnd_std_rand;
    rnd_info.fallback_p_rng = NULL;
    rnd_info.buf = rnd_buf->x;
    rnd_info.length = rnd_buf->len;

    /* Fix rnd_buf->x by shifting it left if necessary */
    if (grp.nbits % 8 != 0) {
        unsigned char shift = 8 - (grp.nbits % 8);
        size_t i;

        for (i = 0; i < rnd_info.length - 1; i++) {
            rnd_buf->x[i] = rnd_buf->x[i] << shift | rnd_buf->x[i+1] >> (8 - shift);
        }

        rnd_buf->x[rnd_info.length-1] <<= shift;
    }

    TEST_ASSERT(mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash->x, hash->len,
                                   mbedtls_test_rnd_buffer_rand, &rnd_info) == result);

    if (result == 0) {
```

## Call pattern 8

```c
/* Invalid signatures: r or s or both one off */
        TEST_EQUAL(mbedtls_mpi_sub_int(&r, &r_check, 1), 0);
        TEST_EQUAL(mbedtls_mpi_add_int(&s, &s_check, 1), 0);

        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);

        /* Invalid signatures: r, s or both (CVE-2022-21449) are zero */
        TEST_EQUAL(mbedtls_mpi_lset(&zero, 0), 0);

        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &zero, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &zero), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &zero, &zero), MBEDTLS_ERR_ECP_VERIFY_FAILED);

        /* Invalid signatures: r, s or both are == N */
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &grp.N, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &grp.N), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &grp.N, &grp.N), MBEDTLS_ERR_ECP_VERIFY_FAILED);

        /* Invalid signatures: r, s or both are negative */
        TEST_EQUAL(mbedtls_mpi_sub_mpi(&r, &r_check, &grp.N), 0);
        TEST_EQUAL(mbedtls_mpi_sub_mpi(&s, &s_check, &grp.N), 0);

        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
```

## Call pattern 9

```c
TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
    }

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    mbedtls_mpi_free(&zero);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECDSA_DETERMINISTIC */
void ecdsa_det_test_vectors(int id, char *d_str, int md_alg, data_t *hash,
                            char *r_str, char *s_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);

    MD_PSA_INIT();

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);

    TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
```

## Call pattern 10

```c
TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
    }

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    mbedtls_mpi_free(&zero);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECDSA_DETERMINISTIC */
void ecdsa_det_test_vectors(int id, char *d_str, int md_alg, data_t *hash,
                            char *r_str, char *s_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);

    MD_PSA_INIT();

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);

    TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);
```

## Call pattern 11

```c
&r, &s_check), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r_check, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
        TEST_EQUAL(mbedtls_ecdsa_verify(&grp, hash->x, hash->len, &Q,
                                        &r, &s), MBEDTLS_ERR_ECP_VERIFY_FAILED);
    }

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    mbedtls_mpi_free(&zero);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECDSA_DETERMINISTIC */
void ecdsa_det_test_vectors(int id, char *d_str, int md_alg, data_t *hash,
                            char *r_str, char *s_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);

    MD_PSA_INIT();

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);

    TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);
```

## Call pattern 12

```c
mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    mbedtls_mpi_free(&zero);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECDSA_DETERMINISTIC */
void ecdsa_det_test_vectors(int id, char *d_str, int md_alg, data_t *hash,
                            char *r_str, char *s_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);

    MD_PSA_INIT();

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);

    TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&r, &r_check) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&s, &s_check) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    MD_PSA_DONE();
}
/* END_CASE */
```

## Call pattern 13

```c
mbedtls_mpi_free(&zero);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ECDSA_DETERMINISTIC */
void ecdsa_det_test_vectors(int id, char *d_str, int md_alg, data_t *hash,
                            char *r_str, char *s_str)
{
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s, r_check, s_check;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r_check); mbedtls_mpi_init(&s_check);

    MD_PSA_INIT();

    TEST_ASSERT(mbedtls_ecp_group_load(&grp, id) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&d, d_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&r_check, r_str) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&s_check, s_str) == 0);

    TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&r, &r_check) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&s, &s_check) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    MD_PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE depends_on:PSA_WANT_ALG_SHA_256 */
```

## Call pattern 14

```c
TEST_ASSERT(
        mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&r, &r_check) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&s, &s_check) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    MD_PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE depends_on:PSA_WANT_ALG_SHA_256 */
void ecdsa_write_read_zero(int id)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char hash[32];
    unsigned char sig[200];
    size_t sig_len, i;

    mbedtls_ecdsa_init(&ctx);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(hash, 0, sizeof(hash));
    memset(sig, 0x2a, sizeof(sig));

    MD_PSA_INIT();

    /* generate signing key */
    TEST_ASSERT(mbedtls_ecdsa_genkey(&ctx, id,
                                     &mbedtls_test_rnd_pseudo_rand,
                                     &rnd_info) == 0);

    /* generate and write signature, then read and verify it */
```

## Call pattern 15

```c
mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                   hash->x, hash->len, md_alg,
                                   mbedtls_test_rnd_std_rand,
                                   NULL)
        == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&r, &r_check) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&s, &s_check) == 0);

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r_check); mbedtls_mpi_free(&s_check);
    MD_PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE depends_on:PSA_WANT_ALG_SHA_256 */
void ecdsa_write_read_zero(int id)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_test_rnd_pseudo_info rnd_info;
    unsigned char hash[32];
    unsigned char sig[200];
    size_t sig_len, i;

    mbedtls_ecdsa_init(&ctx);
    memset(&rnd_info, 0x00, sizeof(mbedtls_test_rnd_pseudo_info));
    memset(hash, 0, sizeof(hash));
    memset(sig, 0x2a, sizeof(sig));

    MD_PSA_INIT();

    /* generate signing key */
    TEST_ASSERT(mbedtls_ecdsa_genkey(&ctx, id,
                                     &mbedtls_test_rnd_pseudo_rand,
                                     &rnd_info) == 0);

    /* generate and write signature, then read and verify it */
    TEST_ASSERT(mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256,
```

## Call pattern 16

```c
mbedtls_ecdsa_free(&ctx);
    MD_PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_verify(int grp_id, char *x, char *y, char *r, char *s, data_t *content, int expected)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_mpi sig_r, sig_s;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_mpi_init(&sig_r);
    mbedtls_mpi_init(&sig_s);

    /* Prepare ECP group context */
    TEST_EQUAL(mbedtls_ecp_group_load(&ctx.grp, grp_id), 0);

    /* Prepare public key */
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.X, x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.Y, y), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&ctx.Q.Z, 1), 0);

    /* Prepare signature R & S */
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_r, r), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_s, s), 0);

    /* Test whether public key has expected validity */
    TEST_EQUAL(mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q),
               expected == MBEDTLS_ERR_ECP_INVALID_KEY ? MBEDTLS_ERR_ECP_INVALID_KEY : 0);

    /* Verification */
    int result = mbedtls_ecdsa_verify(&ctx.grp, content->x, content->len, &ctx.Q, &sig_r, &sig_s);

    TEST_EQUAL(result, expected);
exit:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
}
```

## Call pattern 17

```c
MD_PSA_DONE();
}
/* END_CASE */

/* BEGIN_CASE */
void ecdsa_verify(int grp_id, char *x, char *y, char *r, char *s, data_t *content, int expected)
{
    mbedtls_ecdsa_context ctx;
    mbedtls_mpi sig_r, sig_s;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_mpi_init(&sig_r);
    mbedtls_mpi_init(&sig_s);

    /* Prepare ECP group context */
    TEST_EQUAL(mbedtls_ecp_group_load(&ctx.grp, grp_id), 0);

    /* Prepare public key */
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.X, x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.Y, y), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&ctx.Q.Z, 1), 0);

    /* Prepare signature R & S */
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_r, r), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_s, s), 0);

    /* Test whether public key has expected validity */
    TEST_EQUAL(mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q),
               expected == MBEDTLS_ERR_ECP_INVALID_KEY ? MBEDTLS_ERR_ECP_INVALID_KEY : 0);

    /* Verification */
    int result = mbedtls_ecdsa_verify(&ctx.grp, content->x, content->len, &ctx.Q, &sig_r, &sig_s);

    TEST_EQUAL(result, expected);
exit:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
}
/* END_CASE */
```

## Call pattern 18

```c
mbedtls_mpi sig_r, sig_s;

    mbedtls_ecdsa_init(&ctx);
    mbedtls_mpi_init(&sig_r);
    mbedtls_mpi_init(&sig_s);

    /* Prepare ECP group context */
    TEST_EQUAL(mbedtls_ecp_group_load(&ctx.grp, grp_id), 0);

    /* Prepare public key */
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.X, x), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&ctx.Q.Y, y), 0);
    TEST_EQUAL(mbedtls_mpi_lset(&ctx.Q.Z, 1), 0);

    /* Prepare signature R & S */
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_r, r), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&sig_s, s), 0);

    /* Test whether public key has expected validity */
    TEST_EQUAL(mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q),
               expected == MBEDTLS_ERR_ECP_INVALID_KEY ? MBEDTLS_ERR_ECP_INVALID_KEY : 0);

    /* Verification */
    int result = mbedtls_ecdsa_verify(&ctx.grp, content->x, content->len, &ctx.Q, &sig_r, &sig_s);

    TEST_EQUAL(result, expected);
exit:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
}
/* END_CASE */
```

## Call pattern 19

```c
TEST_EQUAL(mbedtls_test_read_mpi(&sig_s, s), 0);

    /* Test whether public key has expected validity */
    TEST_EQUAL(mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q),
               expected == MBEDTLS_ERR_ECP_INVALID_KEY ? MBEDTLS_ERR_ECP_INVALID_KEY : 0);

    /* Verification */
    int result = mbedtls_ecdsa_verify(&ctx.grp, content->x, content->len, &ctx.Q, &sig_r, &sig_s);

    TEST_EQUAL(result, expected);
exit:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
}
/* END_CASE */
```

## Call pattern 20

```c
/* Test whether public key has expected validity */
    TEST_EQUAL(mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q),
               expected == MBEDTLS_ERR_ECP_INVALID_KEY ? MBEDTLS_ERR_ECP_INVALID_KEY : 0);

    /* Verification */
    int result = mbedtls_ecdsa_verify(&ctx.grp, content->x, content->len, &ctx.Q, &sig_r, &sig_s);

    TEST_EQUAL(result, expected);
exit:
    mbedtls_ecdsa_free(&ctx);
    mbedtls_mpi_free(&sig_r);
    mbedtls_mpi_free(&sig_s);
}
/* END_CASE */
```

