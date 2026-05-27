# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/rsa.c
Knowledge type: api_constraints

## Snippet 1

```c
}

int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen)
{
    int ret, version;
    size_t len, bits;
    unsigned char *p, *end;

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi T;
    mbedtls_mpi_init(&T);
#endif /* !MBEDTLS_RSA_NO_CRT */

    p = (unsigned char *) key;
    end = p + keylen;

    /*
     * This function parses the RSAPrivateKey (PKCS#1)
     *
     *  RSAPrivateKey ::= SEQUENCE {
     *      version           Version,
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER,  -- e
     *      privateExponent   INTEGER,  -- d
     *      prime1            INTEGER,  -- p
     *      prime2            INTEGER,  -- q
     *      exponent1         INTEGER,  -- d mod (p-1)
     *      exponent2         INTEGER,  -- d mod (q-1)
```

## Snippet 2

```c
if ((ret = mbedtls_rsa_check_privkey(rsa)) != 0) {
        goto cleanup;
    }

    if (p != end) {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

cleanup:
#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&T);
#endif /* MBEDTLS_RSA_NO_CRT */

    if (ret != 0) {
        mbedtls_rsa_free(rsa);
    }

    return ret;
}

int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen)
{
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = (unsigned char *) (key + keylen);
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /*
```

## Snippet 3

```c
unsigned char *end = (unsigned char *) (key + keylen);
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /*
     *  RSAPublicKey ::= SEQUENCE {
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER   -- e
     *  }
     */
    mbedtls_mpi_init(&rsa->N);
    mbedtls_mpi_init(&rsa->E);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        goto exit;
    }

    if (end != p + len) {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto exit;
    }

    /* Import N */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
        goto exit;
    }
```

## Snippet 4

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    /*
     *  RSAPublicKey ::= SEQUENCE {
     *      modulus           INTEGER,  -- n
     *      publicExponent    INTEGER   -- e
     *  }
     */
    mbedtls_mpi_init(&rsa->N);
    mbedtls_mpi_init(&rsa->E);

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        goto exit;
    }

    if (end != p + len) {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto exit;
    }

    /* Import N */
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_mpi_read_binary(&rsa->N, p, len)) != 0) {
```

## Snippet 5

```c
ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto exit;
    }

    if (p != end) {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

exit:
    if (ret != 0) {
        mbedtls_mpi_free(&rsa->N);
        mbedtls_mpi_free(&rsa->E);
    }

    return ret;
}

#define MBEDTLS_RSA_WRITE_MPI(m)                               \
    do {                                                        \
        if ((ret = mbedtls_asn1_write_mpi(p, start, m)) < 0) {  \
            goto end_of_export;                                 \
        }                                                       \
        len += ret;                                             \
    } while (0)

int mbedtls_rsa_write_key(const mbedtls_rsa_context *rsa, unsigned char *start,
                          unsigned char **p)
{
```

## Snippet 6

```c
goto exit;
    }

    if (p != end) {
        ret = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }

exit:
    if (ret != 0) {
        mbedtls_mpi_free(&rsa->N);
        mbedtls_mpi_free(&rsa->E);
    }

    return ret;
}

#define MBEDTLS_RSA_WRITE_MPI(m)                               \
    do {                                                        \
        if ((ret = mbedtls_asn1_write_mpi(p, start, m)) < 0) {  \
            goto end_of_export;                                 \
        }                                                       \
        len += ret;                                             \
    } while (0)

int mbedtls_rsa_write_key(const mbedtls_rsa_context *rsa, unsigned char *start,
                          unsigned char **p)
{
    size_t len = 0;
```

## Snippet 7

```c
} while (0)

int mbedtls_rsa_write_key(const mbedtls_rsa_context *rsa, unsigned char *start,
                          unsigned char **p)
{
    size_t len = 0;
    int ret;
#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi DP, DQ, QP;

    mbedtls_mpi_init(&DP); mbedtls_mpi_init(&DQ); mbedtls_mpi_init(&QP);
#endif /* MBEDTLS_RSA_NO_CRT */

    /*
     * Export the parameters one after another to avoid simultaneous copies.
     */

    /* Export QP, DQ, DP */
#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_RSA_WRITE_MPI(&rsa->QP);
    MBEDTLS_RSA_WRITE_MPI(&rsa->DQ);
    MBEDTLS_RSA_WRITE_MPI(&rsa->DP);
#else /* MBEDTLS_RSA_NO_CRT */
    if ((ret = mbedtls_rsa_deduce_crt(&rsa->P, &rsa->Q, &rsa->D, &DP, &DQ, &QP)) != 0) {
        goto end_of_export;
    }
    MBEDTLS_RSA_WRITE_MPI(&QP);
    MBEDTLS_RSA_WRITE_MPI(&DQ);
```

## Snippet 8

```c
/* Export Q, P, D, E, N */
    MBEDTLS_RSA_WRITE_MPI(&rsa->Q);
    MBEDTLS_RSA_WRITE_MPI(&rsa->P);
    MBEDTLS_RSA_WRITE_MPI(&rsa->D);
    MBEDTLS_RSA_WRITE_MPI(&rsa->E);
    MBEDTLS_RSA_WRITE_MPI(&rsa->N);

end_of_export:

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&DP); mbedtls_mpi_free(&DQ); mbedtls_mpi_free(&QP);
#endif /* MBEDTLS_RSA_NO_CRT */

    if (ret < 0) {
        return ret;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 0));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

/*
 *  RSAPublicKey ::= SEQUENCE {
```

## Snippet 9

```c
/*
     * If the modulus is 1024 bit long or shorter, then the security strength of
     * the RSA algorithm is less than or equal to 80 bits and therefore an error
     * rate of 2^-80 is sufficient.
     */
    if (nbits > 1024) {
        prime_quality = MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR;
    }

    mbedtls_mpi_init(&H);

    if (exponent < 3 || nbits % 2 != 0) {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    if (nbits < MBEDTLS_RSA_GEN_KEY_MIN_BITS) {
        ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * find primes P and Q with Q < P so that:
     * 1.  |P-Q| > 2^( nbits / 2 - 100 )
     * 2.  GCD( E, (P-1)*(Q-1) ) == 1
     * 3.  E^-1 mod LCM(P-1, Q-1) > 2^( nbits / 2 )
     */
```

## Snippet 10

```c
ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * find primes P and Q with Q < P so that:
     * 1.  |P-Q| > 2^( nbits / 2 - 100 )
     * 2.  GCD( E, (P-1)*(Q-1) ) == 1
     * 3.  E^-1 mod LCM(P-1, Q-1) > 2^( nbits / 2 )
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&ctx->E, exponent));

    do {
        MBEDTLS_MPI_CHK(mbedtls_mpi_gen_prime(&ctx->P, nbits >> 1,
                                              prime_quality, f_rng, p_rng));

        MBEDTLS_MPI_CHK(mbedtls_mpi_gen_prime(&ctx->Q, nbits >> 1,
                                              prime_quality, f_rng, p_rng));

        /* make sure the difference between p and q is not too small (FIPS 186-4 §B.3.3 step 5.4) */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&H, &ctx->P, &ctx->Q));
        if (mbedtls_mpi_bitlen(&H) <= ((nbits >= 200) ? ((nbits >> 1) - 99) : 0)) {
            continue;
        }

        /* not required by any standards, but some users rely on the fact that P > Q */
        if (H.s < 0) {
            mbedtls_mpi_swap(&ctx->P, &ctx->Q);
```

## Snippet 11

```c
*/
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&ctx->P, &ctx->Q, &ctx->D,
                                           &ctx->DP, &ctx->DQ, &ctx->QP));
#endif /* MBEDTLS_RSA_NO_CRT */

    /* Double-check */
    MBEDTLS_MPI_CHK(mbedtls_rsa_check_privkey(ctx));

cleanup:

    mbedtls_mpi_free(&H);

    if (ret != 0) {
        mbedtls_rsa_free(ctx);

        if ((-ret & ~0x7f) == 0) {
            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_KEY_GEN_FAILED, ret);
        }
        return ret;
    }

    return 0;
}

#endif /* MBEDTLS_GENPRIME */

/*
 * Check a public RSA key
```

## Snippet 12

```c
unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;
    mbedtls_mpi T;

    if (rsa_check_context(ctx, 0 /* public */, 0 /* no blinding */)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&T);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));

    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod_unsafe(&T, &T, &ctx->E, &ctx->N, &ctx->RN));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&T);

    if (ret != 0) {
```

## Snippet 13

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));

    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod_unsafe(&T, &T, &ctx->E, &ctx->N, &ctx->RN));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&T);

    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PUBLIC_FAILED, ret);
    }

    return 0;
}

#if !defined(MBEDTLS_RSA_NO_CRT)
/*
 * Compute T such that T = TP mod P and T = TQ mod Q.
 * (This is the Chinese Remainder Theorem - CRT.)
 */
```

## Snippet 14

```c
ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod_unsafe(&T, &T, &ctx->E, &ctx->N, &ctx->RN));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&T);

    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PUBLIC_FAILED, ret);
    }

    return 0;
}

#if !defined(MBEDTLS_RSA_NO_CRT)
/*
 * Compute T such that T = TP mod P and T = TQ mod Q.
 * (This is the Chinese Remainder Theorem - CRT.)
 */
static int rsa_apply_crt(mbedtls_mpi *T,
                         const mbedtls_mpi *TP,
                         const mbedtls_mpi *TQ,
                         const mbedtls_rsa_context *ctx)
```

## Snippet 15

```c
static int rsa_gen_rand_with_inverse(const mbedtls_rsa_context *ctx,
                                     mbedtls_mpi *A,
                                     mbedtls_mpi *B,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng)
{
#if defined(MBEDTLS_RSA_NO_CRT)
    int ret;
    mbedtls_mpi G;

    mbedtls_mpi_init(&G);

    MBEDTLS_MPI_CHK(mbedtls_mpi_random(A, 1, &ctx->N, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, B, A, &ctx->N));

    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        /* This happens if we're unlucky enough to draw a multiple of P or Q,
         * or if (at least) one of them is not a prime, and we drew a multiple
         * of one of its factors. */
        ret = MBEDTLS_ERR_RSA_RNG_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&G);

    return ret;
#else
```

## Snippet 16

```c
if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        /* This happens if we're unlucky enough to draw a multiple of P or Q,
         * or if (at least) one of them is not a prime, and we drew a multiple
         * of one of its factors. */
        ret = MBEDTLS_ERR_RSA_RNG_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_mpi_free(&G);

    return ret;
#else
    int ret;
    mbedtls_mpi Ap, Aq, Bp, Bq, G;

    mbedtls_mpi_init(&Ap); mbedtls_mpi_init(&Aq);
    mbedtls_mpi_init(&Bp); mbedtls_mpi_init(&Bq);
    mbedtls_mpi_init(&G);

    /*
     * Instead of generating A, B = A^-1 (mod N) directly, generate one Ap, Bp
     * pair (mod P) and one pair (mod Q) and use Chinese Remainder Theorem to
     * construct an A and B from those.
     *
     * This works because the CRT correspondence is a ring isomorphism between
     * Z/NZ (integers mod N) and Z/PZ x Z/QZ (pairs of integers mod P and Q):
```

## Snippet 17

```c
}

cleanup:
    mbedtls_mpi_free(&G);

    return ret;
#else
    int ret;
    mbedtls_mpi Ap, Aq, Bp, Bq, G;

    mbedtls_mpi_init(&Ap); mbedtls_mpi_init(&Aq);
    mbedtls_mpi_init(&Bp); mbedtls_mpi_init(&Bq);
    mbedtls_mpi_init(&G);

    /*
     * Instead of generating A, B = A^-1 (mod N) directly, generate one Ap, Bp
     * pair (mod P) and one pair (mod Q) and use Chinese Remainder Theorem to
     * construct an A and B from those.
     *
     * This works because the CRT correspondence is a ring isomorphism between
     * Z/NZ (integers mod N) and Z/PZ x Z/QZ (pairs of integers mod P and Q):
     * - it is a bijection (one-to-one correspondence);
     * - doing a ring operation (modular +, -, *, ^-1 when possible) on one side is
     *   the same as doing it on the other side.
     * So, drawing uniformly at random an invertible A mod N is the same as
     * drawing uniformly at random pairs of invertible Ap mod P, Aq mod Q.
     */
```

## Snippet 18

```c
cleanup:
    mbedtls_mpi_free(&G);

    return ret;
#else
    int ret;
    mbedtls_mpi Ap, Aq, Bp, Bq, G;

    mbedtls_mpi_init(&Ap); mbedtls_mpi_init(&Aq);
    mbedtls_mpi_init(&Bp); mbedtls_mpi_init(&Bq);
    mbedtls_mpi_init(&G);

    /*
     * Instead of generating A, B = A^-1 (mod N) directly, generate one Ap, Bp
     * pair (mod P) and one pair (mod Q) and use Chinese Remainder Theorem to
     * construct an A and B from those.
     *
     * This works because the CRT correspondence is a ring isomorphism between
     * Z/NZ (integers mod N) and Z/PZ x Z/QZ (pairs of integers mod P and Q):
     * - it is a bijection (one-to-one correspondence);
     * - doing a ring operation (modular +, -, *, ^-1 when possible) on one side is
     *   the same as doing it on the other side.
     * So, drawing uniformly at random an invertible A mod N is the same as
     * drawing uniformly at random pairs of invertible Ap mod P, Aq mod Q.
     */

    /* Generate Ap in [1, P) and compute Bp = Ap^-1 mod P */
```

## Snippet 19

```c
cleanup:
    mbedtls_mpi_free(&G);

    return ret;
#else
    int ret;
    mbedtls_mpi Ap, Aq, Bp, Bq, G;

    mbedtls_mpi_init(&Ap); mbedtls_mpi_init(&Aq);
    mbedtls_mpi_init(&Bp); mbedtls_mpi_init(&Bq);
    mbedtls_mpi_init(&G);

    /*
     * Instead of generating A, B = A^-1 (mod N) directly, generate one Ap, Bp
     * pair (mod P) and one pair (mod Q) and use Chinese Remainder Theorem to
     * construct an A and B from those.
     *
     * This works because the CRT correspondence is a ring isomorphism between
     * Z/NZ (integers mod N) and Z/PZ x Z/QZ (pairs of integers mod P and Q):
     * - it is a bijection (one-to-one correspondence);
     * - doing a ring operation (modular +, -, *, ^-1 when possible) on one side is
     *   the same as doing it on the other side.
     * So, drawing uniformly at random an invertible A mod N is the same as
     * drawing uniformly at random pairs of invertible Ap mod P, Aq mod Q.
     */

    /* Generate Ap in [1, P) and compute Bp = Ap^-1 mod P */
    MBEDTLS_MPI_CHK(mbedtls_mpi_random(&Ap, 1, &ctx->P, f_rng, p_rng));
```

## Snippet 20

```c
/* This can only happen if Q was not a prime. */
        ret = MBEDTLS_ERR_RSA_RNG_FAILED;
        goto cleanup;
    }

    /* Reconstruct A and B */
    MBEDTLS_MPI_CHK(rsa_apply_crt(A, &Ap, &Aq, ctx));
    MBEDTLS_MPI_CHK(rsa_apply_crt(B, &Bp, &Bq, ctx));

cleanup:
    mbedtls_mpi_free(&Ap); mbedtls_mpi_free(&Aq);
    mbedtls_mpi_free(&Bp); mbedtls_mpi_free(&Bq);
    mbedtls_mpi_free(&G);

    return ret;
#endif
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding(mbedtls_rsa_context *ctx,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
```

## Snippet 21

```c
ret = MBEDTLS_ERR_RSA_RNG_FAILED;
        goto cleanup;
    }

    /* Reconstruct A and B */
    MBEDTLS_MPI_CHK(rsa_apply_crt(A, &Ap, &Aq, ctx));
    MBEDTLS_MPI_CHK(rsa_apply_crt(B, &Bp, &Bq, ctx));

cleanup:
    mbedtls_mpi_free(&Ap); mbedtls_mpi_free(&Aq);
    mbedtls_mpi_free(&Bp); mbedtls_mpi_free(&Bq);
    mbedtls_mpi_free(&G);

    return ret;
#endif
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding(mbedtls_rsa_context *ctx,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;
```

## Snippet 22

```c
goto cleanup;
    }

    /* Reconstruct A and B */
    MBEDTLS_MPI_CHK(rsa_apply_crt(A, &Ap, &Aq, ctx));
    MBEDTLS_MPI_CHK(rsa_apply_crt(B, &Bp, &Bq, ctx));

cleanup:
    mbedtls_mpi_free(&Ap); mbedtls_mpi_free(&Aq);
    mbedtls_mpi_free(&Bp); mbedtls_mpi_free(&Bq);
    mbedtls_mpi_free(&G);

    return ret;
#endif
}

/*
 * Generate or update blinding values, see section 10 of:
 *  KOCHER, Paul C. Timing attacks on implementations of Diffie-Hellman, RSA,
 *  DSS, and other systems. In : Advances in Cryptology-CRYPTO'96. Springer
 *  Berlin Heidelberg, 1996. p. 104-113.
 */
static int rsa_prepare_blinding(mbedtls_rsa_context *ctx,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret;

    if (ctx->Vf.p != NULL) {
```

## Snippet 23

```c
* T = T * Vf mod N
 */
static int rsa_unblind(mbedtls_mpi *T, mbedtls_mpi *Vf, const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_mpi_uint mm = mbedtls_mpi_core_montmul_init(N->p);
    const size_t nlimbs = N->n;
    const size_t tlimbs = mbedtls_mpi_core_montmul_working_limbs(nlimbs);
    mbedtls_mpi RR, M_T;

    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&M_T);

    MBEDTLS_MPI_CHK(mbedtls_mpi_core_get_mont_r2_unsafe(&RR, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&M_T, tlimbs));

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(T, nlimbs));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(Vf, nlimbs));

    /* T = T * Vf mod N
     * Reminder: montmul(A, B, N) = A * B * R^-1 mod N
     * Usually both operands are multiplied by R mod N beforehand (by calling
     * `to_mont_rep()` on them), yielding a result that's also * R mod N (aka
     * "in the Montgomery domain"). Here we only multiply one operand by R mod
     * N, so the result is directly what we want - no need to call
     * `from_mont_rep()` on it. */
    mbedtls_mpi_core_to_mont_rep(T->p, T->p, N->p, nlimbs, mm, RR.p, M_T.p);
    mbedtls_mpi_core_montmul(T->p, T->p, Vf->p, nlimbs, N->p, nlimbs, mm, M_T.p);
```

## Snippet 24

```c
*/
static int rsa_unblind(mbedtls_mpi *T, mbedtls_mpi *Vf, const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_mpi_uint mm = mbedtls_mpi_core_montmul_init(N->p);
    const size_t nlimbs = N->n;
    const size_t tlimbs = mbedtls_mpi_core_montmul_working_limbs(nlimbs);
    mbedtls_mpi RR, M_T;

    mbedtls_mpi_init(&RR);
    mbedtls_mpi_init(&M_T);

    MBEDTLS_MPI_CHK(mbedtls_mpi_core_get_mont_r2_unsafe(&RR, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&M_T, tlimbs));

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(T, nlimbs));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(Vf, nlimbs));

    /* T = T * Vf mod N
     * Reminder: montmul(A, B, N) = A * B * R^-1 mod N
     * Usually both operands are multiplied by R mod N beforehand (by calling
     * `to_mont_rep()` on them), yielding a result that's also * R mod N (aka
     * "in the Montgomery domain"). Here we only multiply one operand by R mod
     * N, so the result is directly what we want - no need to call
     * `from_mont_rep()` on it. */
    mbedtls_mpi_core_to_mont_rep(T->p, T->p, N->p, nlimbs, mm, RR.p, M_T.p);
    mbedtls_mpi_core_montmul(T->p, T->p, Vf->p, nlimbs, N->p, nlimbs, mm, M_T.p);
```

## Snippet 25

```c
* Usually both operands are multiplied by R mod N beforehand (by calling
     * `to_mont_rep()` on them), yielding a result that's also * R mod N (aka
     * "in the Montgomery domain"). Here we only multiply one operand by R mod
     * N, so the result is directly what we want - no need to call
     * `from_mont_rep()` on it. */
    mbedtls_mpi_core_to_mont_rep(T->p, T->p, N->p, nlimbs, mm, RR.p, M_T.p);
    mbedtls_mpi_core_montmul(T->p, T->p, Vf->p, nlimbs, N->p, nlimbs, mm, M_T.p);

cleanup:

    mbedtls_mpi_free(&RR);
    mbedtls_mpi_free(&M_T);

    return ret;
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on average.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on average.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
```

## Snippet 26

```c
* `to_mont_rep()` on them), yielding a result that's also * R mod N (aka
     * "in the Montgomery domain"). Here we only multiply one operand by R mod
     * N, so the result is directly what we want - no need to call
     * `from_mont_rep()` on it. */
    mbedtls_mpi_core_to_mont_rep(T->p, T->p, N->p, nlimbs, mm, RR.p, M_T.p);
    mbedtls_mpi_core_montmul(T->p, T->p, Vf->p, nlimbs, N->p, nlimbs, mm, M_T.p);

cleanup:

    mbedtls_mpi_free(&RR);
    mbedtls_mpi_free(&M_T);

    return ret;
}

/*
 * Exponent blinding supposed to prevent side-channel attacks using multiple
 * traces of measurements to recover the RSA key. The more collisions are there,
 * the more bits of the key can be recovered. See [3].
 *
 * Collecting n collisions with m bit long blinding value requires 2^(m-m/n)
 * observations on average.
 *
 * For example with 28 byte blinding to achieve 2 collisions the adversary has
 * to make 2^112 observations on average.
 *
 * (With the currently (as of 2017 April) known best algorithms breaking 2048
 * bit RSA requires approximately as much time as trying out 2^112 random keys.
```

## Snippet 27

```c
if (f_rng == NULL) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (rsa_check_context(ctx, 1 /* private key checks */,
                          1 /* blinding on        */) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /* MPI Initialization */
    mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
```

## Snippet 28

```c
}

    if (rsa_check_context(ctx, 1 /* private key checks */,
                          1 /* blinding on        */) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /* MPI Initialization */
    mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);
```

## Snippet 29

```c
if (rsa_check_context(ctx, 1 /* private key checks */,
                          1 /* blinding on        */) != 0) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    /* MPI Initialization */
    mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */
```

## Snippet 30

```c
}

    /* MPI Initialization */
    mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
```

## Snippet 31

```c
/* MPI Initialization */
    mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }
```

## Snippet 32

```c
mbedtls_mpi_init(&T);

    mbedtls_mpi_init(&P1);
    mbedtls_mpi_init(&Q1);
    mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }
```

## Snippet 33

```c
mbedtls_mpi_init(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * Blinding
     * T = T * Vi mod N
     */
```

## Snippet 34

```c
mbedtls_mpi_init(&D_blind);
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * Blinding
     * T = T * Vi mod N
     */
    MBEDTLS_MPI_CHK(rsa_prepare_blinding(ctx, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T, &T, &ctx->Vi));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, &T, &ctx->N));
```

## Snippet 35

```c
#else
    mbedtls_mpi_init(&DP_blind);
    mbedtls_mpi_init(&DQ_blind);
#endif

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_init(&TP); mbedtls_mpi_init(&TQ);
#endif

    mbedtls_mpi_init(&input_blinded);
    mbedtls_mpi_init(&check_result_blinded);

    /* End of MPI initialization */

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&T, input, ctx->len));
    if (mbedtls_mpi_cmp_mpi(&T, &ctx->N) >= 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    /*
     * Blinding
     * T = T * Vi mod N
     */
    MBEDTLS_MPI_CHK(rsa_prepare_blinding(ctx, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T, &T, &ctx->Vi));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, &T, &ctx->N));
```

## Snippet 36

```c
goto cleanup;
    }

    /*
     * Unblind
     * T = T * Vf mod N
     */
    MBEDTLS_MPI_CHK(rsa_unblind(&T, &ctx->Vf, &ctx->N));

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
```

## Snippet 37

```c
* Unblind
     * T = T * Vf mod N
     */
    MBEDTLS_MPI_CHK(rsa_unblind(&T, &ctx->Vf, &ctx->N));

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
```

## Snippet 38

```c
* T = T * Vf mod N
     */
    MBEDTLS_MPI_CHK(rsa_unblind(&T, &ctx->Vf, &ctx->N));

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);
```

## Snippet 39

```c
*/
    MBEDTLS_MPI_CHK(rsa_unblind(&T, &ctx->Vf, &ctx->N));

    olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);
```

## Snippet 40

```c
olen = ctx->len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&T, output, olen));

cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }
```

## Snippet 41

```c
cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
```

## Snippet 42

```c
cleanup:

    mbedtls_mpi_free(&P1);
    mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
}
```

## Snippet 43

```c
mbedtls_mpi_free(&Q1);
    mbedtls_mpi_free(&R);

#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
}

#if defined(MBEDTLS_PKCS1_V21)
/**
```

## Snippet 44

```c
#if defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&D_blind);
#else
    mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
```

## Snippet 45

```c
mbedtls_mpi_free(&DP_blind);
    mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
```

## Snippet 46

```c
mbedtls_mpi_free(&DQ_blind);
#endif

    mbedtls_mpi_free(&T);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&TP); mbedtls_mpi_free(&TQ);
#endif

    mbedtls_mpi_free(&check_result_blinded);
    mbedtls_mpi_free(&input_blinded);

    if (ret != 0 && ret >= -0x007f) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_RSA_PRIVATE_FAILED, ret);
    }

    return ret;
}

#if defined(MBEDTLS_PKCS1_V21)
/**
 * Generate and apply the MGF1 operation (from PKCS#1 v2.1) to a buffer.
 *
 * \param dst       buffer to mask
 * \param dlen      length of destination buffer
 * \param src       source of the mask generation
 * \param slen      length of the source buffer
 * \param md_alg    message digest to use
```

## Snippet 47

```c
/*
 * Free the components of an RSA key
 */
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}
```

## Snippet 48

```c
/*
 * Free the components of an RSA key
 */
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)
```

## Snippet 49

```c
* Free the components of an RSA key
 */
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)
```

## Snippet 50

```c
*/
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)
```

## Snippet 51

```c
void mbedtls_rsa_free(mbedtls_rsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
```

## Snippet 52

```c
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
```

## Snippet 53

```c
if (ctx == NULL) {
        return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
```

## Snippet 54

```c
return;
    }

    mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128
```

## Snippet 55

```c
mbedtls_mpi_free(&ctx->Vi);
    mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
```

## Snippet 56

```c
mbedtls_mpi_free(&ctx->Vf);
    mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
```

## Snippet 57

```c
mbedtls_mpi_free(&ctx->RN);
    mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
```

## Snippet 58

```c
mbedtls_mpi_free(&ctx->D);
    mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
```

## Snippet 59

```c
mbedtls_mpi_free(&ctx->Q);
    mbedtls_mpi_free(&ctx->P);
    mbedtls_mpi_free(&ctx->E);
    mbedtls_mpi_free(&ctx->N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    mbedtls_mpi_free(&ctx->RQ);
    mbedtls_mpi_free(&ctx->RP);
    mbedtls_mpi_free(&ctx->QP);
    mbedtls_mpi_free(&ctx->DQ);
    mbedtls_mpi_free(&ctx->DP);
#endif /* MBEDTLS_RSA_NO_CRT */
}

#if defined(MBEDTLS_SELF_TEST)


/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
```

## Snippet 60

```c
mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];
#if defined(PSA_WANT_ALG_SHA_1)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }
```

## Snippet 61

```c
unsigned char rsa_ciphertext[KEY_LEN];
#if defined(PSA_WANT_ALG_SHA_1)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0) {
        if (verbose != 0) {
```

## Snippet 62

```c
#if defined(PSA_WANT_ALG_SHA_1)
    unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
```

## Snippet 63

```c
unsigned char sha1sum[20];
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
```

## Snippet 64

```c
#endif

    mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
```

## Snippet 65

```c
mbedtls_mpi K;

    mbedtls_mpi_init(&K);
    mbedtls_rsa_init(&rsa);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.N, 16, RSA_N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.P, 16, RSA_P));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.Q, 16, RSA_Q));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.D, 16, RSA_D));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&rsa.E, 16, RSA_E));
    rsa.len = mbedtls_mpi_size(&rsa.N);

#if !defined(MBEDTLS_RSA_NO_CRT)
    MBEDTLS_MPI_CHK(mbedtls_rsa_deduce_crt(&rsa.P, &rsa.Q, &rsa.D, &rsa.DP, &rsa.DQ, &rsa.QP));
#endif /* !MBEDTLS_RSA_NO_CRT */

    if (verbose != 0) {
        mbedtls_printf("  RSA key validation: ");
    }

    if (mbedtls_rsa_check_pubkey(&rsa) != 0 ||
        mbedtls_rsa_check_privkey(&rsa) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }

        ret = 1;
```

## Snippet 66

```c
if (verbose != 0) {
        mbedtls_printf("passed\n");
    }
#endif /* PSA_WANT_ALG_SHA_1 */

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

cleanup:
    mbedtls_mpi_free(&K);
    mbedtls_rsa_free(&rsa);
#else /* MBEDTLS_PKCS1_V15 */
    ((void) verbose);
#endif /* MBEDTLS_PKCS1_V15 */
    return ret;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_RSA_C */
```

