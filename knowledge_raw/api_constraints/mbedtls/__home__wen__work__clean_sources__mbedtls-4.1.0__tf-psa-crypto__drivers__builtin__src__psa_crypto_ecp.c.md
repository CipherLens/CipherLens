# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/psa_crypto_ecp.c
Knowledge type: api_constraints

## Snippet 1

```c
status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    curve_bytes = PSA_BITS_TO_BYTES(ecp->grp.pbits);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (signature_size < 2 * curve_bytes) {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (PSA_ALG_ECDSA_IS_DETERMINISTIC(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        mbedtls_md_type_t md_alg = mbedtls_md_type_from_psa_alg(hash_alg);
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_ext(
                            &ecp->grp, &r, &s,
                            &ecp->d, hash,
                            hash_length, md_alg,
                            mbedtls_psa_get_random,
                            MBEDTLS_PSA_RANDOM_STATE));
```

## Snippet 2

```c
attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    curve_bytes = PSA_BITS_TO_BYTES(ecp->grp.pbits);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (signature_size < 2 * curve_bytes) {
        ret = MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (PSA_ALG_ECDSA_IS_DETERMINISTIC(alg)) {
#if defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        psa_algorithm_t hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        mbedtls_md_type_t md_alg = mbedtls_md_type_from_psa_alg(hash_alg);
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_ext(
                            &ecp->grp, &r, &s,
                            &ecp->d, hash,
                            hash_length, md_alg,
                            mbedtls_psa_get_random,
                            MBEDTLS_PSA_RANDOM_STATE));
#else
```

## Snippet 3

```c
goto cleanup;
#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */
    } else {
        (void) alg;
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&ecp->grp, &r, &s, &ecp->d,
                                           hash, hash_length,
                                           mbedtls_psa_get_random,
                                           MBEDTLS_PSA_RANDOM_STATE));
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r,
                                             signature,
                                             curve_bytes));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&s,
                                             signature + curve_bytes,
                                             curve_bytes));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    if (ret == 0) {
        *signature_length = 2 * curve_bytes;
    }

    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return mbedtls_to_psa_error(ret);
}
```

## Snippet 4

```c
(void) alg;
        MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&ecp->grp, &r, &s, &ecp->d,
                                           hash, hash_length,
                                           mbedtls_psa_get_random,
                                           MBEDTLS_PSA_RANDOM_STATE));
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r,
                                             signature,
                                             curve_bytes));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&s,
                                             signature + curve_bytes,
                                             curve_bytes));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    if (ret == 0) {
        *signature_length = 2 * curve_bytes;
    }

    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return mbedtls_to_psa_error(ret);
}

psa_status_t mbedtls_psa_ecp_load_public_part(mbedtls_ecp_keypair *ecp)
{
```

## Snippet 5

```c
MBEDTLS_PSA_RANDOM_STATE));
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r,
                                             signature,
                                             curve_bytes));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&s,
                                             signature + curve_bytes,
                                             curve_bytes));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    if (ret == 0) {
        *signature_length = 2 * curve_bytes;
    }

    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return mbedtls_to_psa_error(ret);
}

psa_status_t mbedtls_psa_ecp_load_public_part(mbedtls_ecp_keypair *ecp)
{
    int ret = 0;

    /* Check whether the public part is loaded. If not, load it. */
    if (mbedtls_ecp_is_zero(&ecp->Q)) {
```

## Snippet 6

```c
}

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&r,
                                             signature,
                                             curve_bytes));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&s,
                                             signature + curve_bytes,
                                             curve_bytes));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    if (ret == 0) {
        *signature_length = 2 * curve_bytes;
    }

    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return mbedtls_to_psa_error(ret);
}

psa_status_t mbedtls_psa_ecp_load_public_part(mbedtls_ecp_keypair *ecp)
{
    int ret = 0;

    /* Check whether the public part is loaded. If not, load it. */
    if (mbedtls_ecp_is_zero(&ecp->Q)) {
        ret = mbedtls_ecp_mul(&ecp->grp, &ecp->Q,
```

## Snippet 7

```c
status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    curve_bytes = PSA_BITS_TO_BYTES(ecp->grp.pbits);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (signature_length != 2 * curve_bytes) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_mpi_read_binary(&r,
                                                          signature,
                                                          curve_bytes));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_mpi_read_binary(&s,
                                                          signature + curve_bytes,
                                                          curve_bytes));
```

## Snippet 8

```c
attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &ecp);
    if (status != PSA_SUCCESS) {
        return status;
    }

    curve_bytes = PSA_BITS_TO_BYTES(ecp->grp.pbits);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if (signature_length != 2 * curve_bytes) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_mpi_read_binary(&r,
                                                          signature,
                                                          curve_bytes));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_mpi_read_binary(&s,
                                                          signature + curve_bytes,
                                                          curve_bytes));
    if (status != PSA_SUCCESS) {
```

## Snippet 9

```c
status = mbedtls_psa_ecp_load_public_part(ecp);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_ecdsa_verify(&ecp->grp, hash,
                                                       hash_length, &ecp->Q,
                                                       &r, &s));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return status;
}

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

/****************************************************************/
/* ECDH Key Agreement */
/****************************************************************/

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
static psa_status_t ecdh_write_secret(const mbedtls_ecp_group *grp,
                                      const mbedtls_ecp_point *secret,
```

## Snippet 10

```c
status = mbedtls_psa_ecp_load_public_part(ecp);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = mbedtls_to_psa_error(mbedtls_ecdsa_verify(&ecp->grp, hash,
                                                       hash_length, &ecp->Q,
                                                       &r, &s));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_keypair_free(ecp);
    mbedtls_free(ecp);

    return status;
}

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) */

/****************************************************************/
/* ECDH Key Agreement */
/****************************************************************/

#if defined(MBEDTLS_PSA_BUILTIN_ALG_ECDH)
static psa_status_t ecdh_write_secret(const mbedtls_ecp_group *grp,
                                      const mbedtls_ecp_point *secret,
                                      uint8_t *shared_secret, size_t shared_secret_size,
```

## Snippet 11

```c
uint8_t *shared_secret, size_t shared_secret_size,
                                      size_t *shared_secret_length)
{
    *shared_secret_length = PSA_BITS_TO_BYTES(grp->pbits);
    if (shared_secret_size < *shared_secret_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    return mbedtls_to_psa_error(
        mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY ?
        mbedtls_mpi_write_binary_le(&secret->X, shared_secret, *shared_secret_length) :
        mbedtls_mpi_write_binary(&secret->X, shared_secret, *shared_secret_length));
}

#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
static psa_status_t ecdh_everest_shared_secret(
    const uint8_t *key_buffer, size_t key_buffer_size,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    /* This static function is only called when we know the curve is x25519,
     * so we know key_buffer_size is correct unless the keystore is corrupted.
     * However even in that case we don't want the consequence to be a memory
     * error, so check anyway. This cannot be covered by tests though. */
    if (key_buffer_size != MBEDTLS_X25519_KEY_SIZE_BYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
```

## Snippet 12

```c
size_t *shared_secret_length)
{
    *shared_secret_length = PSA_BITS_TO_BYTES(grp->pbits);
    if (shared_secret_size < *shared_secret_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    return mbedtls_to_psa_error(
        mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY ?
        mbedtls_mpi_write_binary_le(&secret->X, shared_secret, *shared_secret_length) :
        mbedtls_mpi_write_binary(&secret->X, shared_secret, *shared_secret_length));
}

#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
static psa_status_t ecdh_everest_shared_secret(
    const uint8_t *key_buffer, size_t key_buffer_size,
    const uint8_t *peer_key, size_t peer_key_length,
    uint8_t *shared_secret, size_t shared_secret_size,
    size_t *shared_secret_length)
{
    /* This static function is only called when we know the curve is x25519,
     * so we know key_buffer_size is correct unless the keystore is corrupted.
     * However even in that case we don't want the consequence to be a memory
     * error, so check anyway. This cannot be covered by tests though. */
    if (key_buffer_size != MBEDTLS_X25519_KEY_SIZE_BYTES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
```

## Snippet 13

```c
if (status != 0) {
        return mbedtls_to_psa_error(status);
    }

    /* Our implementation of key generation only generates the private key
       which doesn't invlolve any ECC arithmetic operations so number of ops
       is less than 1 but we round up to 1 to differentiate between num ops of
       0 which means no work has been done this facilitates testing. */
    operation->num_ops = 1;

    status = mbedtls_mpi_write_binary(&operation->ecp.d, key_output, key_output_size);

    return mbedtls_to_psa_error(status);
}

psa_status_t mbedtls_psa_ecp_generate_key_iop_abort(
    mbedtls_psa_generate_key_iop_t *operation)
{
    mbedtls_ecp_keypair_free(&operation->ecp);
    operation->num_ops = 0;
    return PSA_SUCCESS;
}

#endif /* MBEDTLS_ECP_RESTARTABLE && MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_ECP_RESTARTABLE) && \
    (defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_IMPORT) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_EXPORT) || \
```

