# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/ecdsa.c
Knowledge type: api_constraints

## Snippet 1

```c
ecdsa_ver_init = 0, /* getting started      */
        ecdsa_ver_muladd,   /* muladd step          */
    } state;
};

/*
 * Init verify restart sub-context
 */
static void ecdsa_restart_ver_init(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    mbedtls_mpi_init(&ctx->u1);
    mbedtls_mpi_init(&ctx->u2);
    ctx->state = ecdsa_ver_init;
}

/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->u1);
    mbedtls_mpi_free(&ctx->u2);

    ecdsa_restart_ver_init(ctx);
```

## Snippet 2

```c
ecdsa_ver_muladd,   /* muladd step          */
    } state;
};

/*
 * Init verify restart sub-context
 */
static void ecdsa_restart_ver_init(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    mbedtls_mpi_init(&ctx->u1);
    mbedtls_mpi_init(&ctx->u2);
    ctx->state = ecdsa_ver_init;
}

/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->u1);
    mbedtls_mpi_free(&ctx->u2);

    ecdsa_restart_ver_init(ctx);
}
```

## Snippet 3

```c
/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->u1);
    mbedtls_mpi_free(&ctx->u2);

    ecdsa_restart_ver_init(ctx);
}

/*
 * Sub-context for ecdsa_sign()
 */
struct mbedtls_ecdsa_restart_sig {
    int sign_tries;
    int key_tries;
    mbedtls_mpi k;          /* per-signature random */
    mbedtls_mpi r;          /* r value              */
    enum {                  /* what to do next?     */
        ecdsa_sig_init = 0, /* getting started      */
        ecdsa_sig_mul,      /* doing ecp_mul()      */
        ecdsa_sig_modn,     /* mod N computations   */
```

## Snippet 4

```c
/*
 * Free the components of a verify restart sub-context
 */
static void ecdsa_restart_ver_free(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->u1);
    mbedtls_mpi_free(&ctx->u2);

    ecdsa_restart_ver_init(ctx);
}

/*
 * Sub-context for ecdsa_sign()
 */
struct mbedtls_ecdsa_restart_sig {
    int sign_tries;
    int key_tries;
    mbedtls_mpi k;          /* per-signature random */
    mbedtls_mpi r;          /* r value              */
    enum {                  /* what to do next?     */
        ecdsa_sig_init = 0, /* getting started      */
        ecdsa_sig_mul,      /* doing ecp_mul()      */
        ecdsa_sig_modn,     /* mod N computations   */
    } state;
```

## Snippet 5

```c
} state;
};

/*
 * Init verify sign sub-context
 */
static void ecdsa_restart_sig_init(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    ctx->sign_tries = 0;
    ctx->key_tries = 0;
    mbedtls_mpi_init(&ctx->k);
    mbedtls_mpi_init(&ctx->r);
    ctx->state = ecdsa_sig_init;
}

/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->k);
    mbedtls_mpi_free(&ctx->r);
}
```

## Snippet 6

```c
};

/*
 * Init verify sign sub-context
 */
static void ecdsa_restart_sig_init(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    ctx->sign_tries = 0;
    ctx->key_tries = 0;
    mbedtls_mpi_init(&ctx->k);
    mbedtls_mpi_init(&ctx->r);
    ctx->state = ecdsa_sig_init;
}

/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->k);
    mbedtls_mpi_free(&ctx->r);
}

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
```

## Snippet 7

```c
/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->k);
    mbedtls_mpi_free(&ctx->r);
}

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Sub-context for ecdsa_sign_det()
 */
struct mbedtls_ecdsa_restart_det {
    mbedtls_hmac_drbg_context rng_ctx;  /* DRBG state   */
    enum {                      /* what to do next?     */
        ecdsa_det_init = 0,     /* getting started      */
        ecdsa_det_sign,         /* make signature       */
    } state;
};

/*
 * Init verify sign_det sub-context
```

## Snippet 8

```c
/*
 * Free the components of a sign restart sub-context
 */
static void ecdsa_restart_sig_free(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->k);
    mbedtls_mpi_free(&ctx->r);
}

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
/*
 * Sub-context for ecdsa_sign_det()
 */
struct mbedtls_ecdsa_restart_det {
    mbedtls_hmac_drbg_context rng_ctx;  /* DRBG state   */
    enum {                      /* what to do next?     */
        ecdsa_det_init = 0,     /* getting started      */
        ecdsa_det_sign,         /* make signature       */
    } state;
};

/*
 * Init verify sign_det sub-context
 */
```

## Snippet 9

```c
if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Make sure d is in range 1..n-1 */
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k); mbedtls_mpi_init(&e);

    ECDSA_RS_ENTER(sig);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;

        /* jump to current step */
        if (rs_ctx->sig->state == ecdsa_sig_mul) {
            goto mul;
        }
        if (rs_ctx->sig->state == ecdsa_sig_modn) {
            goto modn;
```

## Snippet 10

```c
} while (mbedtls_mpi_cmp_int(s, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(r, pr));
    }
#endif

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e);

    ECDSA_RS_LEAVE(sig);

    return ret;
}

/*
 * Compute ECDSA signature of a hashed message
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    /* Use the same RNG for both blinding and ephemeral key generation */
    return mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                          f_rng, p_rng, f_rng, p_rng, NULL);
}
```

## Snippet 11

```c
mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = (grp->nbits + 7) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;

    if ((md_info = mbedtls_md_info_from_type(md_alg)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&h);
    mbedtls_hmac_drbg_init(&rng_ctx);

    ECDSA_RS_ENTER(det);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        /* redirect to our context */
        p_rng = &rs_ctx->det->rng_ctx;

        /* jump to current step */
        if (rs_ctx->det->state == ecdsa_det_sign) {
            goto sign;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
```

## Snippet 12

```c
p_rng = &rs_ctx->det->rng_ctx;

        /* jump to current step */
        if (rs_ctx->det->state == ecdsa_det_sign) {
            goto sign;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, data, grp_len));
    MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    MBEDTLS_MPI_CHK(mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        rs_ctx->det->state = ecdsa_det_sign;
    }

sign:
#endif
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind, rs_ctx);

cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
```

## Snippet 13

```c
/* jump to current step */
        if (rs_ctx->det->state == ecdsa_det_sign) {
            goto sign;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /* Use private key and message hash (reduced) to initialize HMAC_DRBG */
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, data, grp_len));
    MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    MBEDTLS_MPI_CHK(mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        rs_ctx->det->state = ecdsa_det_sign;
    }

sign:
#endif
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind, rs_ctx);

cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&h);
```

## Snippet 14

```c
}

sign:
#endif
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind, rs_ctx);

cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&h);

    ECDSA_RS_LEAVE(det);

    return ret;
}

/*
 * Deterministic signature wrapper
 */
int mbedtls_ecdsa_sign_det_ext(mbedtls_ecp_group *grp, mbedtls_mpi *r,
                               mbedtls_mpi *s, const mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               mbedtls_md_type_t md_alg,
                               int (*f_rng_blind)(void *, unsigned char *,
                                                  size_t),
                               void *p_rng_blind)
{
```

## Snippet 15

```c
const mbedtls_mpi *r,
                                     const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECDSA_RS_ENTER(ver);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
```

## Snippet 16

```c
const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECDSA_RS_ENTER(ver);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
            goto muladd;
```

## Snippet 17

```c
/*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if (mbedtls_mpi_cmp_mpi(&R.X, r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);

    ECDSA_RS_LEAVE(ver);

    return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
```

## Snippet 18

```c
* Step 8: check if v (that is, R.X) is equal to r
     */
    if (mbedtls_mpi_cmp_mpi(&R.X, r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);

    ECDSA_RS_LEAVE(ver);

    return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}
```

## Snippet 19

```c
int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng, rs_ctx));
#else
    (void) md_alg;

    /* Use the same RNG for both blinding and ephemeral key generation */
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));
```

## Snippet 20

```c
void *p_rng,
                                              mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng, rs_ctx));
#else
    (void) md_alg;

    /* Use the same RNG for both blinding and ephemeral key generation */
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
```

## Snippet 21

```c
/* Use the same RNG for both blinding and ephemeral key generation */
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    return mbedtls_ecdsa_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
```

## Snippet 22

```c
/* Use the same RNG for both blinding and ephemeral key generation */
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif /* MBEDTLS_ECDSA_DETERMINISTIC */

    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Compute and write signature
 */
int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    return mbedtls_ecdsa_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
```

## Snippet 23

```c
int mbedtls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p + len != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
```

## Snippet 24

```c
const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (p + len != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto cleanup;
    }

    if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
```

## Snippet 25

```c
}

    /* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if (p != end) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
    }

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }
```

## Snippet 26

```c
/* At this point we know that the buffer starts with a valid signature.
     * Return 0 if the buffer just contains the signature, and a specific
     * error code if the valid signature is followed by more data. */
    if (p != end) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
    }

cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

/*
 * Generate key pair
 */
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }

    return mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d,
```

