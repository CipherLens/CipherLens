# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/ecp.c
Knowledge type: api_constraints

## Snippet 1

```c
#define ECP_RS_ENTER(sub)     (void) rs_ctx;
#define ECP_RS_LEAVE(sub)     (void) rs_ctx;

#endif /* MBEDTLS_ECP_RESTARTABLE */

#if defined(MBEDTLS_ECP_C)
static void mpi_init_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_init(arr++);
    }
}

static void mpi_free_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_free(arr++);
    }
}
#endif /* MBEDTLS_ECP_C */

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2, RFC 8446 sec. 4.2.7)
 *  - size in bits
 *  - readable name
```

## Snippet 2

```c
static void mpi_init_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_init(arr++);
    }
}

static void mpi_free_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_free(arr++);
    }
}
#endif /* MBEDTLS_ECP_C */

/*
 * List of supported curves:
 *  - internal ID
 *  - TLS NamedCurve ID (RFC 4492 sec. 5.1.1, RFC 7071 sec. 2, RFC 8446 sec. 4.2.7)
 *  - size in bits
 *  - readable name
 *
 * Curves are listed in order: largest curves first, and for a given size,
 * fastest curves first.
 *
 * Reminder: update profiles in x509_crt.c and ssl_tls.c when adding a new curve!
 */
static const mbedtls_ecp_curve_info ecp_supported_curves[] =
```

## Snippet 3

```c
} else {
        return MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS;
    }
}

/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
{
    mbedtls_mpi_init(&pt->X);
    mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
```

## Snippet 4

```c
return MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS;
    }
}

/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
{
    mbedtls_mpi_init(&pt->X);
    mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
```

## Snippet 5

```c
}
}

/*
 * Initialize (the components of) a point
 */
void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
{
    mbedtls_mpi_init(&pt->X);
    mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
```

## Snippet 6

```c
mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
```

## Snippet 7

```c
mbedtls_mpi_init(&pt->Z);
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
```

## Snippet 8

```c
}

/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
```

## Snippet 9

```c
/*
 * Initialize (the components of) a group
 */
void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
{
    mbedtls_ecp_group_init(&key->grp);
```

## Snippet 10

```c
grp->T = NULL;
    grp->T_size = 0;
}

/*
 * Initialize (the components of) a key pair
 */
void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
{
    mbedtls_ecp_group_init(&key->grp);
    mbedtls_mpi_init(&key->d);
    mbedtls_ecp_point_init(&key->Q);
}

/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}
```

## Snippet 11

```c
/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}

/*
 * Check that the comb table (grp->T) is static initialized.
 */
static int ecp_group_is_static_comb_table(const mbedtls_ecp_group *grp)
{
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    return grp->T != NULL && grp->T_size == 0;
#else
    (void) grp;
    return 0;
#endif
}
```

## Snippet 12

```c
/*
 * Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}

/*
 * Check that the comb table (grp->T) is static initialized.
 */
static int ecp_group_is_static_comb_table(const mbedtls_ecp_group *grp)
{
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    return grp->T != NULL && grp->T_size == 0;
#else
    (void) grp;
    return 0;
#endif
}

/*
```

## Snippet 13

```c
* Unallocate (the components of) a point
 */
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}

/*
 * Check that the comb table (grp->T) is static initialized.
 */
static int ecp_group_is_static_comb_table(const mbedtls_ecp_group *grp)
{
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    return grp->T != NULL && grp->T_size == 0;
#else
    (void) grp;
    return 0;
#endif
}

/*
 * Unallocate (the components of) a group
```

## Snippet 14

```c
*/
void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
{
    size_t i;

    if (grp == NULL) {
        return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
```

## Snippet 15

```c
void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
{
    size_t i;

    if (grp == NULL) {
        return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
}
```

## Snippet 16

```c
if (grp == NULL) {
        return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
}

/*
 * Unallocate (the components of) a key pair
 */
```

## Snippet 17

```c
return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
}

/*
 * Unallocate (the components of) a key pair
 */
void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
```

## Snippet 18

```c
/*
 * Unallocate (the components of) a key pair
 */
void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
{
    if (key == NULL) {
        return;
    }

    mbedtls_ecp_group_free(&key->grp);
    mbedtls_mpi_free(&key->d);
    mbedtls_ecp_point_free(&key->Q);
}

/*
 * Copy the contents of a point
 */
int mbedtls_ecp_copy(mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->X, &Q->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Y, &Q->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Z, &Q->Z));

cleanup:
    return ret;
}
```

## Snippet 19

```c
{
    return mbedtls_ecp_group_load(dst, src->id);
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Y, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 0));

cleanup:
    return ret;
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
{
    return mbedtls_mpi_cmp_int(&pt->Z, 0) == 0;
}

/*
 * Compare two points lazily
```

## Snippet 20

```c
return mbedtls_ecp_group_load(dst, src->id);
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Y, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 0));

cleanup:
    return ret;
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
{
    return mbedtls_mpi_cmp_int(&pt->Z, 0) == 0;
}

/*
 * Compare two points lazily
 */
```

## Snippet 21

```c
}

/*
 * Set point to zero
 */
int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Y, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 0));

cleanup:
    return ret;
}

/*
 * Tell if a point is zero
 */
int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
{
    return mbedtls_mpi_cmp_int(&pt->Z, 0) == 0;
}

/*
 * Compare two points lazily
 */
int mbedtls_ecp_point_cmp(const mbedtls_ecp_point *P,
```

## Snippet 22

```c
return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

/*
 * Import a non-zero point from ASCII strings
 */
int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->X, radix, x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->Y, radix, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->Z, 1));

cleanup:
    return ret;
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3 and RFC7748)
 */
int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
```

## Snippet 23

```c
}

/*
 * Import a non-zero point from ASCII strings
 */
int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->X, radix, x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->Y, radix, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->Z, 1));

cleanup:
    return ret;
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3 and RFC7748)
 */
int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
```

## Snippet 24

```c
/*
 * Import a non-zero point from ASCII strings
 */
int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->X, radix, x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->Y, radix, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->Z, 1));

cleanup:
    return ret;
}

/*
 * Export a point into unsigned binary data (SEC1 2.3.3 and RFC7748)
 */
int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
        format != MBEDTLS_ECP_PF_COMPRESSED) {
```

## Snippet 25

```c
plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    (void) format; /* Montgomery curves always use the same point format */
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        *olen = plen;
        if (buflen < *olen) {
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&P->X, buf, plen));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        /*
         * Common case: P == 0
         */
        if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
            if (buflen < 1) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x00;
            *olen = 1;

            return 0;
        }
```

## Snippet 26

```c
}

        if (format == MBEDTLS_ECP_PF_UNCOMPRESSED) {
            *olen = 2 * plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x04;
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
        } else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            *olen = plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
        }
    }
#endif

cleanup:
    return ret;
}
```

## Snippet 27

```c
if (format == MBEDTLS_ECP_PF_UNCOMPRESSED) {
            *olen = 2 * plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x04;
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
        } else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            *olen = plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
        }
    }
#endif

cleanup:
    return ret;
}
```

## Snippet 28

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
        } else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            *olen = plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
        }
    }
#endif

cleanup:
    return ret;
}

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit);
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

/*
 * Import a point from unsigned binary data (SEC1 2.3.4 and RFC7748)
```

## Snippet 29

```c
plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (plen != ilen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&pt->X, buf, plen));
        mbedtls_mpi_free(&pt->Y);

        if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
            /* Set most significant bit to 0 as prescribed in RFC7748 §5 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&pt->X, plen * 8 - 1, 0));
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        if (buf[0] == 0x00) {
            if (ilen == 1) {
                return mbedtls_ecp_set_zero(pt);
            } else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
```

## Snippet 30

```c
}

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&pt->X, buf, plen));
        mbedtls_mpi_free(&pt->Y);

        if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
            /* Set most significant bit to 0 as prescribed in RFC7748 §5 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&pt->X, plen * 8 - 1, 0));
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        if (buf[0] == 0x00) {
            if (ilen == 1) {
                return mbedtls_ecp_set_zero(pt);
            } else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
        }

        if (ilen < 1 + plen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&pt->X, buf + 1, plen));
```

## Snippet 31

```c
} else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
        }

        if (ilen < 1 + plen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&pt->X, buf + 1, plen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));

        if (buf[0] == 0x04) {
            /* format == MBEDTLS_ECP_PF_UNCOMPRESSED */
            if (ilen != 1 + plen * 2) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen);
        } else if (buf[0] == 0x02 || buf[0] == 0x03) {
            /* format == MBEDTLS_ECP_PF_COMPRESSED */
            if (ilen != 1 + plen) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_ecp_sw_derive_y(grp, &pt->X, &pt->Y,
                                           (buf[0] & 1));
        } else {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
```

## Snippet 32

```c
#define MPI_ECP_INV(dst, src)                                                 \
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(NULL, (dst), (src), &grp->P))

#define MPI_ECP_MOV(X, A)                                                     \
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, A))

#define MPI_ECP_SHIFT_L(X, count)                                             \
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l_mod(grp, X, count))

#define MPI_ECP_LSET(X, c)                                                    \
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, c))

#define MPI_ECP_CMP_INT(X, c)                                                 \
    mbedtls_mpi_cmp_int(X, c)

#define MPI_ECP_CMP(X, Y)                                                     \
    mbedtls_mpi_cmp_mpi(X, Y)

/* Needs f_rng, p_rng to be defined. */
#define MPI_ECP_RAND(X)                                                       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_random((X), 2, &grp->P, f_rng, p_rng))

/* Conditional negation
 * Needs grp and a temporary MPI tmp to be defined. */
#define MPI_ECP_COND_NEG(X, cond)                                        \
    do                                                                     \
    {                                                                      \
        unsigned char nonzero = mbedtls_mpi_cmp_int((X), 0) != 0;        \
```

## Snippet 33

```c
*/

    /* Check prerequisite p = 3 mod 4 */
    if (mbedtls_mpi_get_bit(&grp->P, 0) != 1 ||
        mbedtls_mpi_get_bit(&grp->P, 1) != 1) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    int ret;
    mbedtls_mpi exp;
    mbedtls_mpi_init(&exp);

    /* use Y to store intermediate result, actually w above */
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, Y, X));

    /* w = y^2 */ /* Y contains y^2 intermediate result */
    /* exp = ((p+1)/4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));
    /* sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(Y, Y /*y^2*/, &exp, &grp->P, NULL));

    /* check parity bit match or else invert Y */
    /* This quick inversion implementation is valid because Y != 0 for all
     * Short Weierstrass curves supported by mbedtls, as each supported curve
     * has an order that is a large prime, so each supported curve does not
     * have any point of order 2, and a point with Y == 0 would be of order 2 */
    if (mbedtls_mpi_get_bit(Y, 0) != parity_bit) {
```

## Snippet 34

```c
/* This quick inversion implementation is valid because Y != 0 for all
     * Short Weierstrass curves supported by mbedtls, as each supported curve
     * has an order that is a large prime, so each supported curve does not
     * have any point of order 2, and a point with Y == 0 would be of order 2 */
    if (mbedtls_mpi_get_bit(Y, 0) != parity_bit) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(Y, &grp->P, Y));
    }

cleanup:

    mbedtls_mpi_free(&exp);
    return ret;
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with countermeasures against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
```

## Snippet 35

```c
* Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt)
{
    if (MPI_ECP_CMP_INT(&pt->Z, 0) == 0) {
        return 0;
    }

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T;
    mbedtls_mpi_init(&T);

    MPI_ECP_INV(&T,       &pt->Z);            /* T   <-          1 / Z   */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);    /* Y'  <- Y*T    = Y / Z   */
    MPI_ECP_SQR(&T,       &T);                /* T   <- T^2    = 1 / Z^2 */
    MPI_ECP_MUL(&pt->X,   &pt->X,     &T);    /* X   <- X  * T = X / Z^2 */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);    /* Y'' <- Y' * T = Y / Z^3 */

    MPI_ECP_LSET(&pt->Z, 1);

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
}

/*
```

## Snippet 36

```c
MPI_ECP_INV(&T,       &pt->Z);            /* T   <-          1 / Z   */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);    /* Y'  <- Y*T    = Y / Z   */
    MPI_ECP_SQR(&T,       &T);                /* T   <- T^2    = 1 / Z^2 */
    MPI_ECP_MUL(&pt->X,   &pt->X,     &T);    /* X   <- X  * T = X / Z^2 */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);    /* Y'' <- Y' * T = Y / Z^3 */

    MPI_ECP_LSET(&pt->Z, 1);

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
}

/*
 * Normalize jacobian coordinates of an array of (pointers to) points,
 * using Montgomery's trick to perform only one inversion mod P.
 * (See for example Cohen's "A Course in Computational Algebraic Number
 * Theory", Algorithm 10.3.4.)
 *
 * Warning: fails (returning an error) if one of the points is zero!
 * This should never happen, see choice of w in ecp_mul_comb().
 *
 * Cost: 1N(t) := 1I + (6t - 3)M + 1S
 */
static int ecp_normalize_jac_many(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *T[], size_t T_size)
```

## Snippet 37

```c
}

    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    mbedtls_mpi *c, t;

    if ((c = mbedtls_calloc(T_size, sizeof(mbedtls_mpi))) == NULL) {
        return MBEDTLS_ERR_ECP_ALLOC_FAILED;
    }

    mbedtls_mpi_init(&t);

    mpi_init_many(c, T_size);
    /*
     * c[i] = Z_0 * ... * Z_i,   i = 0,..,n := T_size-1
     */
    MPI_ECP_MOV(&c[0], &T[0]->Z);
    for (i = 1; i < T_size; i++) {
        MPI_ECP_MUL(&c[i], &c[i-1], &T[i]->Z);
    }

    /*
     * c[n] = 1 / (Z_0 * ... * Z_n) mod P
     */
    MPI_ECP_INV(&c[T_size-1], &c[T_size-1]);

    for (i = T_size - 1;; i--) {
        /* At the start of iteration i (note that i decrements), we have
```

## Snippet 38

```c
MPI_ECP_LSET(&T[i]->Z, 1);

        if (i == 0) {
            break;
        }
    }

cleanup:

    mbedtls_mpi_free(&t);
    mpi_free_many(c, T_size);
    mbedtls_free(c);

    return ret;
}

/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *Q,
                               unsigned char inv)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);
```

## Snippet 39

```c
/*
 * Conditional point inversion: Q -> -Q = (Q.X, -Q.Y, Q.Z) without leak.
 * "inv" must be 0 (don't invert) or 1 (invert) or the result will be invalid
 */
static int ecp_safe_invert_jac(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *Q,
                               unsigned char inv)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    MPI_ECP_COND_NEG(&Q->Y, inv);

cleanup:
    mbedtls_mpi_free(&tmp);
    return ret;
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
```

## Snippet 40

```c
mbedtls_ecp_point *Q,
                               unsigned char inv)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    MPI_ECP_COND_NEG(&Q->Y, inv);

cleanup:
    mbedtls_mpi_free(&tmp);
    return ret;
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * Based on http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-1998-cmo-2 .
 *
 * We follow the variable naming fairly closely. The formula variations that trade a MUL for a SQR
 * (plus a few ADDs) aren't useful as our bignum implementation doesn't distinguish squaring.
 *
 * Standard optimizations are applied when curve parameter A is one of { 0, -3 }.
 *
 * Cost: 1D := 3M + 4S          (A ==  0)
 *             4M + 4S          (A == -3)
 *             3M + 6S + 1a     otherwise
 */
```

## Snippet 41

```c
* This is sort of the reverse operation of ecp_normalize_jac().
 *
 * This countermeasure was first suggested in [2].
 */
static int ecp_randomize_jac(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;

    mbedtls_mpi_init(&l);

    /* Generate l such that 1 < l < p */
    MPI_ECP_RAND(&l);

    /* Z' = l * Z */
    MPI_ECP_MUL(&pt->Z,   &pt->Z,     &l);

    /* Y' = l * Y */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);

    /* X' = l^2 * X */
    MPI_ECP_SQR(&l,       &l);
    MPI_ECP_MUL(&pt->X,   &pt->X,     &l);

    /* Y'' = l^2 * Y' = l^3 * Y */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);
```

## Snippet 42

```c
MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);

    /* X' = l^2 * X */
    MPI_ECP_SQR(&l,       &l);
    MPI_ECP_MUL(&pt->X,   &pt->X,     &l);

    /* Y'' = l^2 * Y' = l^3 * Y */
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);

cleanup:
    mbedtls_mpi_free(&l);

    if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    return ret;
}

/*
 * Check and define parameters used by the comb method (see below for details)
 */
#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

/* d = ceil( n / w ) */
#define COMB_MAX_D      (MBEDTLS_ECP_MAX_BITS + 1) / 2
```

## Snippet 43

```c
MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_INV + 6 * j - 2);

    MBEDTLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, j));

    /* Free Z coordinate (=1 after normalization) to save RAM.
     * This makes T[i] invalid as mbedtls_ecp_points, but this is OK
     * since from this point onwards, they are only accessed indirectly
     * via the getter function ecp_select_comb() which does set the
     * target's Z coordinate to 1. */
    for (i = 0; i < T_size; i++) {
        mbedtls_mpi_free(&T[i].Z);
    }

cleanup:

    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL &&
        ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
        if (rs_ctx->rsm->state == ecp_rsm_pre_dbl) {
            rs_ctx->rsm->i = j;
        }
    }
#endif

    return ret;
}
```

## Snippet 44

```c
static int ecp_comb_recode_scalar(const mbedtls_ecp_group *grp,
                                  const mbedtls_mpi *m,
                                  unsigned char k[COMB_MAX_D + 1],
                                  size_t d,
                                  unsigned char w,
                                  unsigned char *parity_trick)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, mm;

    mbedtls_mpi_init(&M);
    mbedtls_mpi_init(&mm);

    /* N is always odd (see above), just make extra sure */
    if (mbedtls_mpi_get_bit(&grp->N, 0) != 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* do we need the parity trick? */
    *parity_trick = (mbedtls_mpi_get_bit(m, 0) == 0);

    /* execute parity fix in constant time */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&M, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&mm, &grp->N, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&M, &mm, *parity_trick));

    /* actual scalar recoding */
    ecp_comb_recode_core(k, d, w, &M);
```

## Snippet 45

```c
const mbedtls_mpi *m,
                                  unsigned char k[COMB_MAX_D + 1],
                                  size_t d,
                                  unsigned char w,
                                  unsigned char *parity_trick)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, mm;

    mbedtls_mpi_init(&M);
    mbedtls_mpi_init(&mm);

    /* N is always odd (see above), just make extra sure */
    if (mbedtls_mpi_get_bit(&grp->N, 0) != 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* do we need the parity trick? */
    *parity_trick = (mbedtls_mpi_get_bit(m, 0) == 0);

    /* execute parity fix in constant time */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&M, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&mm, &grp->N, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&M, &mm, *parity_trick));

    /* actual scalar recoding */
    ecp_comb_recode_core(k, d, w, &M);
```

## Snippet 46

```c
/* execute parity fix in constant time */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&M, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&mm, &grp->N, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&M, &mm, *parity_trick));

    /* actual scalar recoding */
    ecp_comb_recode_core(k, d, w, &M);

cleanup:
    mbedtls_mpi_free(&mm);
    mbedtls_mpi_free(&M);

    return ret;
}

/*
 * Perform comb multiplication (for short Weierstrass curves)
 * once the auxiliary table has been pre-computed.
 *
 * Scalar recoding may use a parity trick that makes us compute -m * P,
 * if that is the case we'll need to recover m * P at the end.
 */
static int ecp_mul_comb_after_precomp(const mbedtls_ecp_group *grp,
                                      mbedtls_ecp_point *R,
                                      const mbedtls_mpi *m,
                                      const mbedtls_ecp_point *T,
                                      unsigned char T_size,
```

## Snippet 47

```c
/* execute parity fix in constant time */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&M, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&mm, &grp->N, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&M, &mm, *parity_trick));

    /* actual scalar recoding */
    ecp_comb_recode_core(k, d, w, &M);

cleanup:
    mbedtls_mpi_free(&mm);
    mbedtls_mpi_free(&M);

    return ret;
}

/*
 * Perform comb multiplication (for short Weierstrass curves)
 * once the auxiliary table has been pre-computed.
 *
 * Scalar recoding may use a parity trick that makes us compute -m * P,
 * if that is the case we'll need to recover m * P at the end.
 */
static int ecp_mul_comb_after_precomp(const mbedtls_ecp_group *grp,
                                      mbedtls_ecp_point *R,
                                      const mbedtls_mpi *m,
                                      const mbedtls_ecp_point *T,
                                      unsigned char T_size,
                                      unsigned char w,
```

## Snippet 48

```c
* This is sort of the reverse operation of ecp_normalize_mxz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 2M
 */
static int ecp_randomize_mxz(const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;
    mbedtls_mpi_init(&l);

    /* Generate l such that 1 < l < p */
    MPI_ECP_RAND(&l);

    MPI_ECP_MUL(&P->X, &P->X, &l);
    MPI_ECP_MUL(&P->Z, &P->Z, &l);

cleanup:
    mbedtls_mpi_free(&l);

    if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    return ret;
}

/*
```

## Snippet 49

```c
mbedtls_mpi l;
    mbedtls_mpi_init(&l);

    /* Generate l such that 1 < l < p */
    MPI_ECP_RAND(&l);

    MPI_ECP_MUL(&P->X, &P->X, &l);
    MPI_ECP_MUL(&P->Z, &P->Z, &l);

cleanup:
    mbedtls_mpi_free(&l);

    if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    return ret;
}

/*
 * Double-and-add: R = 2P, S = P + Q, with d = X(P - Q),
 * for Montgomery curves in x/z coordinates.
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/montgom/xz/ladder/mladd-1987-m.op3
 * with
 * d =  X1
 * P = (X2, Z2)
 * Q = (X3, Z3)
 * R = (X4, Z4)
```

## Snippet 50

```c
const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    unsigned char b;
    mbedtls_ecp_point RP;
    mbedtls_mpi PX;
    mbedtls_mpi tmp[4];
    mbedtls_ecp_point_init(&RP); mbedtls_mpi_init(&PX);

    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Save PX and read from P before writing to R, in case P == R */
    MPI_ECP_MOV(&PX, &P->X);
    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&RP, P));

    /* Set R to zero in modified x/z coordinates */
    MPI_ECP_LSET(&R->X, 1);
    MPI_ECP_LSET(&R->Z, 0);
    mbedtls_mpi_free(&R->Y);

    /* RP.X might be slightly larger than P, so reduce it */
```

## Snippet 51

```c
return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    /* Save PX and read from P before writing to R, in case P == R */
    MPI_ECP_MOV(&PX, &P->X);
    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&RP, P));

    /* Set R to zero in modified x/z coordinates */
    MPI_ECP_LSET(&R->X, 1);
    MPI_ECP_LSET(&R->Z, 0);
    mbedtls_mpi_free(&R->Y);

    /* RP.X might be slightly larger than P, so reduce it */
    MOD_ADD(&RP.X);

    /* Randomize coordinates of the starting point */
    MBEDTLS_MPI_CHK(ecp_randomize_mxz(grp, &RP, f_rng, p_rng));

    /* Loop invariant: R = result so far, RP = R + P */
    i = grp->nbits + 1; /* one past the (zero-based) required msb for private keys */
    while (i-- > 0) {
        b = mbedtls_mpi_get_bit(m, i);
        /*
         *  if (b) R = 2R + P else R = 2R,
         * which is:
         *  if (b) double_add( RP, R, RP, R )
         *  else   double_add( R, RP, R, RP )
         * but using safe conditional swaps to avoid leaks
```

## Snippet 52

```c
MPI_ECP_COND_SWAP(&R->X, &RP.X, b);
        MPI_ECP_COND_SWAP(&R->Z, &RP.Z, b);
        MBEDTLS_MPI_CHK(ecp_double_add_mxz(grp, R, &RP, R, &RP, &PX, tmp));
        MPI_ECP_COND_SWAP(&R->X, &RP.X, b);
        MPI_ECP_COND_SWAP(&R->Z, &RP.Z, b);
    }

    MBEDTLS_MPI_CHK(ecp_normalize_mxz(grp, R));

cleanup:
    mbedtls_ecp_point_free(&RP); mbedtls_mpi_free(&PX);

    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    return ret;
}

#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

/*
 * Restartable multiplication R = m * P
 *
 * This internal function can be called without an RNG in case where we know
 * the inputs are not sensitive.
 */
static int ecp_mul_restartable_internal(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                        mbedtls_ecp_restart_ctx *rs_ctx)
```

## Snippet 53

```c
mbedtls_mpi YY, RHS;

    /* pt coordinates must be normalized for our checks */
    if (mbedtls_mpi_cmp_int(&pt->X, 0) < 0 ||
        mbedtls_mpi_cmp_int(&pt->Y, 0) < 0 ||
        mbedtls_mpi_cmp_mpi(&pt->X, &grp->P) >= 0 ||
        mbedtls_mpi_cmp_mpi(&pt->Y, &grp->P) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_mpi_init(&YY); mbedtls_mpi_init(&RHS);

    /*
     * YY = Y^2
     * RHS = X^3 + A X + B
     */
    MPI_ECP_SQR(&YY,  &pt->Y);
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, &RHS, &pt->X));

    if (MPI_ECP_CMP(&YY, &RHS) != 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
    }

cleanup:

    mbedtls_mpi_free(&YY); mbedtls_mpi_free(&RHS);

    return ret;
```

## Snippet 54

```c
*/
    MPI_ECP_SQR(&YY,  &pt->Y);
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, &RHS, &pt->X));

    if (MPI_ECP_CMP(&YY, &RHS) != 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
    }

cleanup:

    mbedtls_mpi_free(&YY); mbedtls_mpi_free(&RHS);

    return ret;
}
#endif /* MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
/*
 * R = m * P with shortcuts for m == 0, m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int mbedtls_ecp_mul_shortcuts(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *P,
                                     mbedtls_ecp_restart_ctx *rs_ctx)
{
```

## Snippet 55

```c
* NOT constant-time - ONLY for short Weierstrass!
 */
static int mbedtls_ecp_mul_shortcuts(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *P,
                                     mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    if (mbedtls_mpi_cmp_int(m, 0) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(R));
    } else if (mbedtls_mpi_cmp_int(m, 1) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, P));
    } else if (mbedtls_mpi_cmp_int(m, -1) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, P));
        MPI_ECP_NEG(&R->Y);
    } else {
        MBEDTLS_MPI_CHK(ecp_mul_restartable_internal(grp, R, m, P,
                                                     NULL, NULL, rs_ctx));
    }

cleanup:
```

## Snippet 56

```c
} else if (mbedtls_mpi_cmp_int(m, -1) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, P));
        MPI_ECP_NEG(&R->Y);
    } else {
        MBEDTLS_MPI_CHK(ecp_mul_restartable_internal(grp, R, m, P,
                                                     NULL, NULL, rs_ctx));
    }

cleanup:
    mbedtls_mpi_free(&tmp);

    return ret;
}

/*
 * Restartable linear combination
 * NOT constant-time
 */
int mbedtls_ecp_muladd_restartable(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point mP;
    mbedtls_ecp_point *pmP = &mP;
```

## Snippet 57

```c
* This is recommended by the "May the Fourth" paper:
 * https://eprint.iacr.org/2017/806.pdf
 * Those points are never sent by an honest peer.
 */
static int ecp_check_bad_points_mx(const mbedtls_mpi *X, const mbedtls_mpi *P,
                                   const mbedtls_ecp_group_id grp_id)
{
    int ret;
    mbedtls_mpi XmP;

    mbedtls_mpi_init(&XmP);

    /* Reduce X mod P so that we only need to check values less than P.
     * We know X < 2^256 so we can proceed by subtraction. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&XmP, X));
    while (mbedtls_mpi_cmp_mpi(&XmP, P) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&XmP, &XmP, P));
    }

    /* Check against the known bad values that are less than P. For Curve448
     * these are 0, 1 and -1. For Curve25519 we check the values less than P
     * from the following list: https://cr.yp.to/ecdh.html#validate */
    if (mbedtls_mpi_cmp_int(&XmP, 1) <= 0) {  /* takes care of 0 and 1 */
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
```

## Snippet 58

```c
/* Final check: check if XmP + 1 is P (final because it changes XmP!) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&XmP, &XmP, 1));
    if (mbedtls_mpi_cmp_mpi(&XmP, P) == 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_mpi_free(&XmP);

    return ret;
}

/*
 * Check validity of a public key for Montgomery curves with x-only schemes
 */
static int ecp_check_pubkey_mx(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt)
{
    /* [Curve25519 p. 5] Just check X is the correct number of bytes */
    /* Allow any public value, if it's too big then we'll just reduce it mod p
     * (RFC 7748 sec. 5 para. 3). */
    if (mbedtls_mpi_size(&pt->X) > (grp->nbits + 7) / 8) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    /* Implicit in all standards (as they don't consider negative numbers):
```

## Snippet 59

```c
}
#endif

    if (ret == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(&key->grp, &key->d));
    }

cleanup:

    if (ret != 0) {
        mbedtls_mpi_free(&key->d);
    }

    return ret;
}

int mbedtls_ecp_write_key_ext(const mbedtls_ecp_keypair *key,
                              size_t *olen, unsigned char *buf, size_t buflen)
{
    size_t len = (key->grp.nbits + 7) / 8;
    if (len > buflen) {
        /* For robustness, ensure *olen <= buflen even on error. */
        *olen = 0;
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    *olen = len;

    /* Private key not set */
```

## Snippet 60

```c
}
    *olen = len;

    /* Private key not set */
    if (key->d.n == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_mpi_write_binary_le(&key->d, buf, len);
    }
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return mbedtls_mpi_write_binary(&key->d, buf, len);
    }
#endif

    /* Private key set but no recognized curve type? This shouldn't happen. */
    return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
}

/*
 * Write a public key.
 */
int mbedtls_ecp_write_public_key(const mbedtls_ecp_keypair *key,
```

## Snippet 61

```c
}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_mpi_write_binary_le(&key->d, buf, len);
    }
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return mbedtls_mpi_write_binary(&key->d, buf, len);
    }
#endif

    /* Private key set but no recognized curve type? This shouldn't happen. */
    return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
}

/*
 * Write a public key.
 */
int mbedtls_ecp_write_public_key(const mbedtls_ecp_keypair *key,
                                 int format, size_t *olen,
                                 unsigned char *buf, size_t buflen)
{
    return mbedtls_ecp_point_write_binary(&key->grp, &key->Q,
                                          format, olen, buf, buflen);
}
```

## Snippet 62

```c
const char *const *exponents,
                           size_t n_exponents)
{
    int ret = 0;
    size_t i = 0;
    unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
    add_count = 0;
    dbl_count = 0;
    mul_count = 0;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(m, 16, exponents[0]));
    MBEDTLS_MPI_CHK(self_test_adjust_exponent(grp, m));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

    for (i = 1; i < n_exponents; i++) {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(m, 16, exponents[i]));
        MBEDTLS_MPI_CHK(self_test_adjust_exponent(grp, m));
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

        if (add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
```

## Snippet 63

```c
MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

    for (i = 1; i < n_exponents; i++) {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(m, 16, exponents[i]));
        MBEDTLS_MPI_CHK(self_test_adjust_exponent(grp, m));
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

        if (add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev) {
            ret = 1;
            break;
        }
    }

cleanup:
    if (verbose != 0) {
        if (ret != 0) {
            mbedtls_printf("failed (%u)\n", (unsigned int) i);
        } else {
            mbedtls_printf("passed\n");
```

## Snippet 64

```c
"5715ECCE24583F7A7023C24164390586842E816D7280A49EF6DF4EAE6B280BF8",
        "41A2B017516F6D254E1F002BCCBADD54BE30F8CEC737A0E912B4963B6BA74460",
        "5555555555555555555555555555555555555555555555555555555555555550",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8",
    };
#endif /* MBEDTLS_ECP_MONTGOMERY_ENABLED */

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&m);

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    /* Use secp256r1 if available, or any available curve */
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
#else
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, mbedtls_ecp_curve_list()->grp_id));
#endif

    if (verbose != 0) {
        mbedtls_printf("  ECP SW test #1 (constant op_count, base point G): ");
    }
    /* Do a dummy multiplication first to trigger precomputation */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m, 2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &P, &m, &grp.G, self_test_rng, NULL));
    ret = self_test_point(verbose,
                          &grp, &R, &m, &grp.G,
```

## Snippet 65

```c
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
#else
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, mbedtls_ecp_curve_list()->grp_id));
#endif

    if (verbose != 0) {
        mbedtls_printf("  ECP SW test #1 (constant op_count, base point G): ");
    }
    /* Do a dummy multiplication first to trigger precomputation */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m, 2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &P, &m, &grp.G, self_test_rng, NULL));
    ret = self_test_point(verbose,
                          &grp, &R, &m, &grp.G,
                          sw_exponents,
                          sizeof(sw_exponents) / sizeof(sw_exponents[0]));
    if (ret != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("  ECP SW test #2 (constant op_count, other point): ");
    }
    /* We computed P = 2G last time, use it */
    ret = self_test_point(verbose,
                          &grp, &R, &m, &P,
                          sw_exponents,
                          sizeof(sw_exponents) / sizeof(sw_exponents[0]));
```

## Snippet 66

```c
cleanup:

    if (ret < 0 && verbose != 0) {
        mbedtls_printf("Unexpected error, return code = %08X\n", (unsigned int) ret);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&m);

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return ret;
#else /* MBEDTLS_ECP_C */
    (void) verbose;
    return 0;
#endif /* MBEDTLS_ECP_C */
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_ECP_LIGHT */
```

