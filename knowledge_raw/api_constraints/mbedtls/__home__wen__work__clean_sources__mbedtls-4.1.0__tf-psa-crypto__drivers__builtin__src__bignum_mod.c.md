# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/bignum_mod.c
Knowledge type: api_constraints

## Snippet 1

```c
static int set_mont_const_square(const mbedtls_mpi_uint **X,
                                 const mbedtls_mpi_uint *A,
                                 size_t limbs)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi N;
    mbedtls_mpi RR;
    *X = NULL;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);

    if (A == NULL || limbs == 0 || limbs >= (MBEDTLS_MPI_MAX_LIMBS / 2) - 2) {
        goto cleanup;
    }

    if (mbedtls_mpi_grow(&N, limbs)) {
        goto cleanup;
    }

    memcpy(N.p, A, sizeof(mbedtls_mpi_uint) * limbs);

    ret = mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N);

    if (ret == 0) {
        *X = RR.p;
        RR.p = NULL;
```

## Snippet 2

```c
static int set_mont_const_square(const mbedtls_mpi_uint **X,
                                 const mbedtls_mpi_uint *A,
                                 size_t limbs)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi N;
    mbedtls_mpi RR;
    *X = NULL;

    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&RR);

    if (A == NULL || limbs == 0 || limbs >= (MBEDTLS_MPI_MAX_LIMBS / 2) - 2) {
        goto cleanup;
    }

    if (mbedtls_mpi_grow(&N, limbs)) {
        goto cleanup;
    }

    memcpy(N.p, A, sizeof(mbedtls_mpi_uint) * limbs);

    ret = mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N);

    if (ret == 0) {
        *X = RR.p;
        RR.p = NULL;
    }
```

## Snippet 3

```c
memcpy(N.p, A, sizeof(mbedtls_mpi_uint) * limbs);

    ret = mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N);

    if (ret == 0) {
        *X = RR.p;
        RR.p = NULL;
    }

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
    ret = (ret != 0) ? MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : 0;
    return ret;
}

static inline void standard_modulus_setup(mbedtls_mpi_mod_modulus *N,
                                          const mbedtls_mpi_uint *p,
                                          size_t p_limbs,
                                          mbedtls_mpi_mod_rep_selector int_rep)
{
    N->p = p;
    N->limbs = p_limbs;
    N->bits = mbedtls_mpi_core_bitlen(p, p_limbs);
    N->int_rep = int_rep;
}

int mbedtls_mpi_mod_modulus_setup(mbedtls_mpi_mod_modulus *N,
```

## Snippet 4

```c
ret = mbedtls_mpi_core_get_mont_r2_unsafe(&RR, &N);

    if (ret == 0) {
        *X = RR.p;
        RR.p = NULL;
    }

cleanup:
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&RR);
    ret = (ret != 0) ? MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED : 0;
    return ret;
}

static inline void standard_modulus_setup(mbedtls_mpi_mod_modulus *N,
                                          const mbedtls_mpi_uint *p,
                                          size_t p_limbs,
                                          mbedtls_mpi_mod_rep_selector int_rep)
{
    N->p = p;
    N->limbs = p_limbs;
    N->bits = mbedtls_mpi_core_bitlen(p, p_limbs);
    N->int_rep = int_rep;
}

int mbedtls_mpi_mod_modulus_setup(mbedtls_mpi_mod_modulus *N,
                                  const mbedtls_mpi_uint *p,
```

