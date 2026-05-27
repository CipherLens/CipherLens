# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/ecjpake.c
Knowledge type: api_constraints

## Snippet 1

```c
ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_init(&ctx->grp);
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;

    mbedtls_ecp_point_init(&ctx->Xm1);
    mbedtls_ecp_point_init(&ctx->Xm2);
    mbedtls_ecp_point_init(&ctx->Xp1);
    mbedtls_ecp_point_init(&ctx->Xp2);
    mbedtls_ecp_point_init(&ctx->Xp);

    mbedtls_mpi_init(&ctx->xm1);
    mbedtls_mpi_init(&ctx->xm2);
    mbedtls_mpi_init(&ctx->s);
}

/*
 * Free context
 */
void mbedtls_ecjpake_free(mbedtls_ecjpake_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
```

## Snippet 2

```c
mbedtls_ecp_group_init(&ctx->grp);
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;

    mbedtls_ecp_point_init(&ctx->Xm1);
    mbedtls_ecp_point_init(&ctx->Xm2);
    mbedtls_ecp_point_init(&ctx->Xp1);
    mbedtls_ecp_point_init(&ctx->Xp2);
    mbedtls_ecp_point_init(&ctx->Xp);

    mbedtls_mpi_init(&ctx->xm1);
    mbedtls_mpi_init(&ctx->xm2);
    mbedtls_mpi_init(&ctx->s);
}

/*
 * Free context
 */
void mbedtls_ecjpake_free(mbedtls_ecjpake_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
    mbedtls_ecp_point_free(&ctx->Xm2);
```

## Snippet 3

```c
ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;

    mbedtls_ecp_point_init(&ctx->Xm1);
    mbedtls_ecp_point_init(&ctx->Xm2);
    mbedtls_ecp_point_init(&ctx->Xp1);
    mbedtls_ecp_point_init(&ctx->Xp2);
    mbedtls_ecp_point_init(&ctx->Xp);

    mbedtls_mpi_init(&ctx->xm1);
    mbedtls_mpi_init(&ctx->xm2);
    mbedtls_mpi_init(&ctx->s);
}

/*
 * Free context
 */
void mbedtls_ecjpake_free(mbedtls_ecjpake_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
    mbedtls_ecp_point_free(&ctx->Xm2);
    mbedtls_ecp_point_free(&ctx->Xp1);
```

## Snippet 4

```c
ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
    mbedtls_ecp_point_free(&ctx->Xm2);
    mbedtls_ecp_point_free(&ctx->Xp1);
    mbedtls_ecp_point_free(&ctx->Xp2);
    mbedtls_ecp_point_free(&ctx->Xp);

    mbedtls_mpi_free(&ctx->xm1);
    mbedtls_mpi_free(&ctx->xm2);
    mbedtls_mpi_free(&ctx->s);
}

/*
 * Setup context
 */
int mbedtls_ecjpake_setup(mbedtls_ecjpake_context *ctx,
                          mbedtls_ecjpake_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *secret,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (role != MBEDTLS_ECJPAKE_CLIENT && role != MBEDTLS_ECJPAKE_SERVER) {
```

## Snippet 5

```c
ctx->md_type = MBEDTLS_MD_NONE;
    mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
    mbedtls_ecp_point_free(&ctx->Xm2);
    mbedtls_ecp_point_free(&ctx->Xp1);
    mbedtls_ecp_point_free(&ctx->Xp2);
    mbedtls_ecp_point_free(&ctx->Xp);

    mbedtls_mpi_free(&ctx->xm1);
    mbedtls_mpi_free(&ctx->xm2);
    mbedtls_mpi_free(&ctx->s);
}

/*
 * Setup context
 */
int mbedtls_ecjpake_setup(mbedtls_ecjpake_context *ctx,
                          mbedtls_ecjpake_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *secret,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (role != MBEDTLS_ECJPAKE_CLIENT && role != MBEDTLS_ECJPAKE_SERVER) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
```

## Snippet 6

```c
mbedtls_ecp_group_free(&ctx->grp);

    mbedtls_ecp_point_free(&ctx->Xm1);
    mbedtls_ecp_point_free(&ctx->Xm2);
    mbedtls_ecp_point_free(&ctx->Xp1);
    mbedtls_ecp_point_free(&ctx->Xp2);
    mbedtls_ecp_point_free(&ctx->Xp);

    mbedtls_mpi_free(&ctx->xm1);
    mbedtls_mpi_free(&ctx->xm2);
    mbedtls_mpi_free(&ctx->s);
}

/*
 * Setup context
 */
int mbedtls_ecjpake_setup(mbedtls_ecjpake_context *ctx,
                          mbedtls_ecjpake_role role,
                          mbedtls_md_type_t hash,
                          mbedtls_ecp_group_id curve,
                          const unsigned char *secret,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (role != MBEDTLS_ECJPAKE_CLIENT && role != MBEDTLS_ECJPAKE_SERVER) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
```

## Snippet 7

```c
const unsigned char **p,
                            const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point V, VV;
    mbedtls_mpi r, h;
    size_t r_len;

    mbedtls_ecp_point_init(&V);
    mbedtls_ecp_point_init(&VV);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&h);

    /*
     * struct {
     *     ECPoint V;
     *     opaque r<1..2^8-1>;
     * } ECSchnorrZKP;
     */
    if (end < *p) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(mbedtls_ecp_tls_read_point(grp, &V, p, (size_t) (end - *p)));

    if (end < *p || (size_t) (end - *p) < 1) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
```

## Snippet 8

```c
const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point V, VV;
    mbedtls_mpi r, h;
    size_t r_len;

    mbedtls_ecp_point_init(&V);
    mbedtls_ecp_point_init(&VV);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&h);

    /*
     * struct {
     *     ECPoint V;
     *     opaque r<1..2^8-1>;
     * } ECSchnorrZKP;
     */
    if (end < *p) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(mbedtls_ecp_tls_read_point(grp, &V, p, (size_t) (end - *p)));

    if (end < *p || (size_t) (end - *p) < 1) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
```

## Snippet 9

```c
&VV, &h, X, &r, G));

    if (mbedtls_ecp_point_cmp(&VV, &V) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&V);
    mbedtls_ecp_point_free(&VV);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&h);

    return ret;
}

/*
 * Generate ZKP (7.4.2.3.2) and write it as ECSchnorrZKP (7.4.2.2.2)
 */
static int ecjpake_zkp_write(const mbedtls_md_type_t md_type,
                             const mbedtls_ecp_group *grp,
                             const int pf,
                             const mbedtls_ecp_point *G,
                             const mbedtls_mpi *x,
                             const mbedtls_ecp_point *X,
                             const char *id,
                             unsigned char **p,
                             const unsigned char *end,
```

## Snippet 10

```c
if (mbedtls_ecp_point_cmp(&VV, &V) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&V);
    mbedtls_ecp_point_free(&VV);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&h);

    return ret;
}

/*
 * Generate ZKP (7.4.2.3.2) and write it as ECSchnorrZKP (7.4.2.2.2)
 */
static int ecjpake_zkp_write(const mbedtls_md_type_t md_type,
                             const mbedtls_ecp_group *grp,
                             const int pf,
                             const mbedtls_ecp_point *G,
                             const mbedtls_mpi *x,
                             const mbedtls_ecp_point *X,
                             const char *id,
                             unsigned char **p,
                             const unsigned char *end,
                             int (*f_rng)(void *, unsigned char *, size_t),
```

## Snippet 11

```c
mbedtls_ecp_point V;
    mbedtls_mpi v;
    mbedtls_mpi h; /* later recycled to hold r */
    size_t len;

    if (end < *p) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    mbedtls_ecp_point_init(&V);
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&h);

    /* Compute signature */
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_keypair_base((mbedtls_ecp_group *) grp,
                                                 G, &v, &V, f_rng, p_rng));
    MBEDTLS_MPI_CHK(ecjpake_hash(md_type, grp, pf, G, &V, X, id, &h));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &h, x));     /* x*h */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&h, &v, &h));     /* v - x*h */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&h, &h, &grp->N));     /* r */

    /* Write it out */
    MBEDTLS_MPI_CHK(mbedtls_ecp_tls_write_point(grp, &V,
                                                pf, &len, *p, (size_t) (end - *p)));
    *p += len;

    len = mbedtls_mpi_size(&h);   /* actually r */
    if (end < *p || (size_t) (end - *p) < 1 + len || len > 255) {
```

## Snippet 12

```c
mbedtls_mpi v;
    mbedtls_mpi h; /* later recycled to hold r */
    size_t len;

    if (end < *p) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    mbedtls_ecp_point_init(&V);
    mbedtls_mpi_init(&v);
    mbedtls_mpi_init(&h);

    /* Compute signature */
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_keypair_base((mbedtls_ecp_group *) grp,
                                                 G, &v, &V, f_rng, p_rng));
    MBEDTLS_MPI_CHK(ecjpake_hash(md_type, grp, pf, G, &V, X, id, &h));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&h, &h, x));     /* x*h */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&h, &v, &h));     /* v - x*h */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&h, &h, &grp->N));     /* r */

    /* Write it out */
    MBEDTLS_MPI_CHK(mbedtls_ecp_tls_write_point(grp, &V,
                                                pf, &len, *p, (size_t) (end - *p)));
    *p += len;

    len = mbedtls_mpi_size(&h);   /* actually r */
    if (end < *p || (size_t) (end - *p) < 1 + len || len > 255) {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
```

## Snippet 13

```c
pf, &len, *p, (size_t) (end - *p)));
    *p += len;

    len = mbedtls_mpi_size(&h);   /* actually r */
    if (end < *p || (size_t) (end - *p) < 1 + len || len > 255) {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    *(*p)++ = MBEDTLS_BYTE_0(len);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, *p, len));     /* r */
    *p += len;

cleanup:
    mbedtls_ecp_point_free(&V);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&h);

    return ret;
}

/*
 * Parse a ECJPAKEKeyKP (7.4.2.2.1) and check proof
 * Output: verified public key X
 */
static int ecjpake_kkp_read(const mbedtls_md_type_t md_type,
                            const mbedtls_ecp_group *grp,
                            const int pf,
```

## Snippet 14

```c
ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    *(*p)++ = MBEDTLS_BYTE_0(len);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, *p, len));     /* r */
    *p += len;

cleanup:
    mbedtls_ecp_point_free(&V);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&h);

    return ret;
}

/*
 * Parse a ECJPAKEKeyKP (7.4.2.2.1) and check proof
 * Output: verified public key X
 */
static int ecjpake_kkp_read(const mbedtls_md_type_t md_type,
                            const mbedtls_ecp_group *grp,
                            const int pf,
                            const mbedtls_ecp_point *G,
                            mbedtls_ecp_point *X,
                            const char *id,
                            const unsigned char **p,
                            const unsigned char *end)
```

## Snippet 15

```c
goto cleanup;
    }

    *(*p)++ = MBEDTLS_BYTE_0(len);
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, *p, len));     /* r */
    *p += len;

cleanup:
    mbedtls_ecp_point_free(&V);
    mbedtls_mpi_free(&v);
    mbedtls_mpi_free(&h);

    return ret;
}

/*
 * Parse a ECJPAKEKeyKP (7.4.2.2.1) and check proof
 * Output: verified public key X
 */
static int ecjpake_kkp_read(const mbedtls_md_type_t md_type,
                            const mbedtls_ecp_group *grp,
                            const int pf,
                            const mbedtls_ecp_point *G,
                            mbedtls_ecp_point *X,
                            const char *id,
                            const unsigned char **p,
                            const unsigned char *end)
{
```

## Snippet 16

```c
* Compute the sum of three points R = A + B + C
 */
static int ecjpake_ecp_add3(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point *A,
                            const mbedtls_ecp_point *B,
                            const mbedtls_ecp_point *C)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi one;

    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, A, &one, B));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, R, &one, C));

cleanup:
    mbedtls_mpi_free(&one);

    return ret;
}

/*
 * Read and process second round message (C: 7.4.2.5, S: 7.4.2.6)
 */
int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
```

## Snippet 17

```c
static int ecjpake_ecp_add3(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point *A,
                            const mbedtls_ecp_point *B,
                            const mbedtls_ecp_point *C)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi one;

    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, A, &one, B));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, R, &one, C));

cleanup:
    mbedtls_mpi_free(&one);

    return ret;
}

/*
 * Read and process second round message (C: 7.4.2.5, S: 7.4.2.6)
 */
int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
```

## Snippet 18

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi one;

    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, A, &one, B));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(grp, R, &one, R, &one, C));

cleanup:
    mbedtls_mpi_free(&one);

    return ret;
}

/*
 * Read and process second round message (C: 7.4.2.5, S: 7.4.2.6)
 */
int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context *ctx,
                                   const unsigned char *buf,
                                   size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point G;    /* C: GB, S: GA */
```

## Snippet 19

```c
static int ecjpake_mul_secret(mbedtls_mpi *R, int sign,
                              const mbedtls_mpi *X,
                              const mbedtls_mpi *S,
                              const mbedtls_mpi *N,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi b; /* Blinding value, then s + N * blinding */

    mbedtls_mpi_init(&b);

    /* b = s + rnd-128-bit * N */
    MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&b, 16, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &b, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&b, &b, S));

    /* R = sign * X * b mod N */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(R, X, &b));
    R->s *= sign;
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(R, R, N));

cleanup:
    mbedtls_mpi_free(&b);

    return ret;
}
```

## Snippet 20

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&b, 16, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&b, &b, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&b, &b, S));

    /* R = sign * X * b mod N */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(R, X, &b));
    R->s *= sign;
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(R, R, N));

cleanup:
    mbedtls_mpi_free(&b);

    return ret;
}

/*
 * Generate and write the second round message (S: 7.4.2.5, C: 7.4.2.6)
 */
int mbedtls_ecjpake_write_round_two(mbedtls_ecjpake_context *ctx,
                                    unsigned char *buf, size_t len, size_t *olen,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point G;    /* C: GA, S: GB */
    mbedtls_ecp_point Xm;   /* C: Xc, S: Xs */
    mbedtls_mpi xm;         /* C: xc, S: xs */
    unsigned char *p = buf;
```

## Snippet 21

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point G;    /* C: GA, S: GB */
    mbedtls_ecp_point Xm;   /* C: Xc, S: Xs */
    mbedtls_mpi xm;         /* C: xc, S: xs */
    unsigned char *p = buf;
    const unsigned char *end = buf + len;
    size_t ec_len;

    mbedtls_ecp_point_init(&G);
    mbedtls_ecp_point_init(&Xm);
    mbedtls_mpi_init(&xm);

    /*
     * First generate private/public key pair (S: 7.4.2.5.1, C: 7.4.2.6.1)
     *
     * Client:  GA = X1  + X3  + X4  | xs = x2  * s | Xc = xc * GA
     * Server:  GB = X3  + X1  + X2  | xs = x4  * s | Xs = xs * GB
     * Unified: G  = Xm1 + Xp1 + Xp2 | xm = xm2 * s | Xm = xm * G
     */
    MBEDTLS_MPI_CHK(ecjpake_ecp_add3(&ctx->grp, &G,
                                     &ctx->Xp1, &ctx->Xp2, &ctx->Xm1));
    MBEDTLS_MPI_CHK(ecjpake_mul_secret(&xm, 1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, &Xm, &xm, &G, f_rng, p_rng));

    /*
     * Now write things out
     *
```

## Snippet 22

```c
MBEDTLS_MPI_CHK(ecjpake_zkp_write(ctx->md_type, &ctx->grp,
                                      ctx->point_format,
                                      &G, &xm, &Xm, ID_MINE,
                                      &p, end, f_rng, p_rng));

    *olen = (size_t) (p - buf);

cleanup:
    mbedtls_ecp_point_free(&G);
    mbedtls_ecp_point_free(&Xm);
    mbedtls_mpi_free(&xm);

    return ret;
}

/*
 * Derive PMS (7.4.2.7 / 7.4.2.8)
 */
static int mbedtls_ecjpake_derive_k(mbedtls_ecjpake_context *ctx,
                                    mbedtls_ecp_point *K,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi m_xm2_s, one;

    mbedtls_mpi_init(&m_xm2_s);
    mbedtls_mpi_init(&one);
```

## Snippet 23

```c
* Derive PMS (7.4.2.7 / 7.4.2.8)
 */
static int mbedtls_ecjpake_derive_k(mbedtls_ecjpake_context *ctx,
                                    mbedtls_ecp_point *K,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi m_xm2_s, one;

    mbedtls_mpi_init(&m_xm2_s);
    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    /*
     * Client:  K = ( Xs - X4  * x2  * s ) * x2
     * Server:  K = ( Xc - X2  * x4  * s ) * x4
     * Unified: K = ( Xp - Xp2 * xm2 * s ) * xm2
     */
    MBEDTLS_MPI_CHK(ecjpake_mul_secret(&m_xm2_s, -1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, K,
                                       &one, &ctx->Xp,
                                       &m_xm2_s, &ctx->Xp2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, K, &ctx->xm2, K,
                                    f_rng, p_rng));
```

## Snippet 24

```c
*/
static int mbedtls_ecjpake_derive_k(mbedtls_ecjpake_context *ctx,
                                    mbedtls_ecp_point *K,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi m_xm2_s, one;

    mbedtls_mpi_init(&m_xm2_s);
    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    /*
     * Client:  K = ( Xs - X4  * x2  * s ) * x2
     * Server:  K = ( Xc - X2  * x4  * s ) * x4
     * Unified: K = ( Xp - Xp2 * xm2 * s ) * xm2
     */
    MBEDTLS_MPI_CHK(ecjpake_mul_secret(&m_xm2_s, -1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, K,
                                       &one, &ctx->Xp,
                                       &m_xm2_s, &ctx->Xp2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, K, &ctx->xm2, K,
                                    f_rng, p_rng));

cleanup:
```

## Snippet 25

```c
mbedtls_ecp_point *K,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi m_xm2_s, one;

    mbedtls_mpi_init(&m_xm2_s);
    mbedtls_mpi_init(&one);

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));

    /*
     * Client:  K = ( Xs - X4  * x2  * s ) * x2
     * Server:  K = ( Xc - X2  * x4  * s ) * x4
     * Unified: K = ( Xp - Xp2 * xm2 * s ) * xm2
     */
    MBEDTLS_MPI_CHK(ecjpake_mul_secret(&m_xm2_s, -1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, K,
                                       &one, &ctx->Xp,
                                       &m_xm2_s, &ctx->Xp2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, K, &ctx->xm2, K,
                                    f_rng, p_rng));

cleanup:
    mbedtls_mpi_free(&m_xm2_s);
    mbedtls_mpi_free(&one);
```

## Snippet 26

```c
*/
    MBEDTLS_MPI_CHK(ecjpake_mul_secret(&m_xm2_s, -1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, K,
                                       &one, &ctx->Xp,
                                       &m_xm2_s, &ctx->Xp2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, K, &ctx->xm2, K,
                                    f_rng, p_rng));

cleanup:
    mbedtls_mpi_free(&m_xm2_s);
    mbedtls_mpi_free(&one);

    return ret;
}

int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point K;
    unsigned char kx[MBEDTLS_ECP_MAX_BYTES];
    size_t x_bytes;

    *olen = mbedtls_md_get_size_from_type(ctx->md_type);
    if (len < *olen) {
```

## Snippet 27

```c
MBEDTLS_MPI_CHK(ecjpake_mul_secret(&m_xm2_s, -1, &ctx->xm2, &ctx->s,
                                       &ctx->grp.N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&ctx->grp, K,
                                       &one, &ctx->Xp,
                                       &m_xm2_s, &ctx->Xp2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&ctx->grp, K, &ctx->xm2, K,
                                    f_rng, p_rng));

cleanup:
    mbedtls_mpi_free(&m_xm2_s);
    mbedtls_mpi_free(&one);

    return ret;
}

int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context *ctx,
                                  unsigned char *buf, size_t len, size_t *olen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point K;
    unsigned char kx[MBEDTLS_ECP_MAX_BYTES];
    size_t x_bytes;

    *olen = mbedtls_md_get_size_from_type(ctx->md_type);
    if (len < *olen) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
```

## Snippet 28

```c
mbedtls_ecp_point_init(&K);

    ret = mbedtls_ecjpake_derive_k(ctx, &K, f_rng, p_rng);
    if (ret) {
        goto cleanup;
    }

    /* PMS = SHA-256( K.X ) */
    x_bytes = (ctx->grp.pbits + 7) / 8;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K.X, kx, x_bytes));
    MBEDTLS_MPI_CHK(mbedtls_ecjpake_compute_hash(ctx->md_type,
                                                 kx, x_bytes, buf));

cleanup:
    mbedtls_ecp_point_free(&K);

    return ret;
}

int mbedtls_ecjpake_write_shared_key(mbedtls_ecjpake_context *ctx,
                                     unsigned char *buf, size_t len, size_t *olen,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point K;
```

