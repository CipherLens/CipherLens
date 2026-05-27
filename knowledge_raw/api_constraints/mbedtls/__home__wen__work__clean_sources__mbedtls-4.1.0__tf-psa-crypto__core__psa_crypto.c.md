# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/core/psa_crypto.c
Knowledge type: api_constraints

## Snippet 1

```c
size_t *signature_length)
{
#if (defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(MBEDTLS_ECP_RESTARTABLE)

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Ensure max_ops is set to the current value (or default). */
    mbedtls_psa_interruptible_set_max_ops(psa_interruptible_get_max_ops());

    if (signature_size < 2 * operation->coordinate_bytes) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (PSA_ALG_ECDSA_IS_DETERMINISTIC(operation->alg)) {

#if defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        status = mbedtls_to_psa_error(
            mbedtls_ecdsa_sign_det_restartable(&operation->ctx->grp,
                                               &r,
                                               &s,
```

## Snippet 2

```c
{
#if (defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(MBEDTLS_ECP_RESTARTABLE)

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r;
    mbedtls_mpi s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Ensure max_ops is set to the current value (or default). */
    mbedtls_psa_interruptible_set_max_ops(psa_interruptible_get_max_ops());

    if (signature_size < 2 * operation->coordinate_bytes) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (PSA_ALG_ECDSA_IS_DETERMINISTIC(operation->alg)) {

#if defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)
        status = mbedtls_to_psa_error(
            mbedtls_ecdsa_sign_det_restartable(&operation->ctx->grp,
                                               &r,
                                               &s,
                                               &operation->ctx->d,
```

## Snippet 3

```c
MBEDTLS_PSA_RANDOM_STATE,
                                           &operation->restart_ctx));
    }

    /* Hide the fact that the restart context only holds a delta of number of
     * ops done during the last operation, not an absolute value. */
    operation->num_ops += operation->restart_ctx.ecp.ops_done;

    if (status == PSA_SUCCESS) {
        status =  mbedtls_to_psa_error(
            mbedtls_mpi_write_binary(&r,
                                     signature,
                                     operation->coordinate_bytes)
            );

        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status =  mbedtls_to_psa_error(
            mbedtls_mpi_write_binary(&s,
                                     signature +
                                     operation->coordinate_bytes,
                                     operation->coordinate_bytes)
            );

        if (status != PSA_SUCCESS) {
            goto exit;
```

## Snippet 4

```c
mbedtls_mpi_write_binary(&r,
                                     signature,
                                     operation->coordinate_bytes)
            );

        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status =  mbedtls_to_psa_error(
            mbedtls_mpi_write_binary(&s,
                                     signature +
                                     operation->coordinate_bytes,
                                     operation->coordinate_bytes)
            );

        if (status != PSA_SUCCESS) {
            goto exit;
        }

        *signature_length = operation->coordinate_bytes * 2;

        status = PSA_SUCCESS;
    }

exit:

    mbedtls_mpi_free(&r);
```

## Snippet 5

```c
goto exit;
        }

        *signature_length = operation->coordinate_bytes * 2;

        status = PSA_SUCCESS;
    }

exit:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return status;

 #else

    (void) operation;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}
```

## Snippet 6

```c
}

        *signature_length = operation->coordinate_bytes * 2;

        status = PSA_SUCCESS;
    }

exit:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return status;

 #else

    (void) operation;
    (void) signature;
    (void) signature_size;
    (void) signature_length;

    return PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

psa_status_t mbedtls_psa_sign_hash_abort(
```

## Snippet 7

```c
if (!can_do_interruptible_sign_verify(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if (defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(MBEDTLS_ECP_RESTARTABLE)

    mbedtls_ecdsa_restart_init(&operation->restart_ctx);
    mbedtls_mpi_init(&operation->r);
    mbedtls_mpi_init(&operation->s);

    /* Ensure num_ops is zero'ed in case of context re-use. */
    operation->num_ops = 0;

    status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &operation->ctx);

    if (status != PSA_SUCCESS) {
        return status;
    }

    coordinate_bytes = PSA_BITS_TO_BYTES(operation->ctx->grp.nbits);
```

## Snippet 8

```c
if (!can_do_interruptible_sign_verify(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#if (defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA)) && \
    defined(MBEDTLS_ECP_RESTARTABLE)

    mbedtls_ecdsa_restart_init(&operation->restart_ctx);
    mbedtls_mpi_init(&operation->r);
    mbedtls_mpi_init(&operation->s);

    /* Ensure num_ops is zero'ed in case of context re-use. */
    operation->num_ops = 0;

    status = mbedtls_psa_ecp_load_representation(attributes->type,
                                                 attributes->bits,
                                                 key_buffer,
                                                 key_buffer_size,
                                                 &operation->ctx);

    if (status != PSA_SUCCESS) {
        return status;
    }

    coordinate_bytes = PSA_BITS_TO_BYTES(operation->ctx->grp.nbits);

    if (signature_length != 2 * coordinate_bytes) {
```

## Snippet 9

```c
if (operation->ctx) {
        mbedtls_ecdsa_free(operation->ctx);
        mbedtls_free(operation->ctx);
        operation->ctx = NULL;
    }

    mbedtls_ecdsa_restart_free(&operation->restart_ctx);

    operation->num_ops = 0;

    mbedtls_mpi_free(&operation->r);
    mbedtls_mpi_free(&operation->s);

    return PSA_SUCCESS;

#else
    (void) operation;

    return PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

static psa_status_t psa_generate_random_internal(uint8_t *output,
                                                 size_t output_size)
{
```

## Snippet 10

```c
mbedtls_ecdsa_free(operation->ctx);
        mbedtls_free(operation->ctx);
        operation->ctx = NULL;
    }

    mbedtls_ecdsa_restart_free(&operation->restart_ctx);

    operation->num_ops = 0;

    mbedtls_mpi_free(&operation->r);
    mbedtls_mpi_free(&operation->s);

    return PSA_SUCCESS;

#else
    (void) operation;

    return PSA_ERROR_NOT_SUPPORTED;

#endif /* defined(MBEDTLS_PSA_BUILTIN_ALG_ECDSA) ||
        * defined(MBEDTLS_PSA_BUILTIN_ALG_DETERMINISTIC_ECDSA) &&
        * defined( MBEDTLS_ECP_RESTARTABLE ) */
}

static psa_status_t psa_generate_random_internal(uint8_t *output,
                                                 size_t output_size)
{
    GUARD_MODULE_INITIALIZED;
```

## Snippet 11

```c
)
{
    unsigned key_out_of_range = 1;
    mbedtls_mpi k;
    mbedtls_mpi diff_N_2;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t m;
    size_t m_bytes = 0;

    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&diff_N_2);

    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(
        slot->attr.type);
    mbedtls_ecp_group_id grp_id =
        mbedtls_ecc_group_from_psa(curve, bits);

    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        ret = MBEDTLS_ERR_ASN1_INVALID_DATA;
        goto cleanup;
    }

    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_group_init(&ecp_group);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&ecp_group, grp_id));
```

## Snippet 12

```c
{
    unsigned key_out_of_range = 1;
    mbedtls_mpi k;
    mbedtls_mpi diff_N_2;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t m;
    size_t m_bytes = 0;

    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&diff_N_2);

    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_FAMILY(
        slot->attr.type);
    mbedtls_ecp_group_id grp_id =
        mbedtls_ecc_group_from_psa(curve, bits);

    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        ret = MBEDTLS_ERR_ASN1_INVALID_DATA;
        goto cleanup;
    }

    mbedtls_ecp_group ecp_group;
    mbedtls_ecp_group_init(&ecp_group);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&ecp_group, grp_id));

    /* N is the boundary of the private key domain (ecp_group.N). */
```

## Snippet 13

```c
/* 4. If k > N - 2, discard the result and return to step 1.
         *    Result of comparison is returned. When it indicates error
         *    then this function is called again.
         */
        MBEDTLS_MPI_CHK(mbedtls_mpi_lt_mpi_ct(&diff_N_2, &k, &key_out_of_range));
    }

    /* 5. Output k + 1 as the private key. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&k, &k, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&k, *data, m_bytes));
cleanup:
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }
    if (status != PSA_SUCCESS) {
        mbedtls_zeroize_and_free(*data, m_bytes);
        *data = NULL;
    }
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&diff_N_2);
    return status;
}

/* ECC keys on a Montgomery elliptic curve draws a byte string whose length
 * is determined by the curve, and sets the mandatory bits accordingly. That is:
 *
 * - Curve25519 (PSA_ECC_FAMILY_MONTGOMERY, 255 bits):
```

## Snippet 14

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&k, &k, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&k, *data, m_bytes));
cleanup:
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }
    if (status != PSA_SUCCESS) {
        mbedtls_zeroize_and_free(*data, m_bytes);
        *data = NULL;
    }
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&diff_N_2);
    return status;
}

/* ECC keys on a Montgomery elliptic curve draws a byte string whose length
 * is determined by the curve, and sets the mandatory bits accordingly. That is:
 *
 * - Curve25519 (PSA_ECC_FAMILY_MONTGOMERY, 255 bits):
 *   draw a 32-byte string and process it as specified in
 *   Elliptic Curves for Security [RFC7748] §5.
 *
 * - Curve448 (PSA_ECC_FAMILY_MONTGOMERY, 448 bits):
 *   draw a 56-byte string and process it as specified in [RFC7748] §5.
 *
 * Note: Function allocates memory for *data buffer, so given *data should be
 *       always NULL.
 */
```

## Snippet 15

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&k, *data, m_bytes));
cleanup:
    if (ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }
    if (status != PSA_SUCCESS) {
        mbedtls_zeroize_and_free(*data, m_bytes);
        *data = NULL;
    }
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&diff_N_2);
    return status;
}

/* ECC keys on a Montgomery elliptic curve draws a byte string whose length
 * is determined by the curve, and sets the mandatory bits accordingly. That is:
 *
 * - Curve25519 (PSA_ECC_FAMILY_MONTGOMERY, 255 bits):
 *   draw a 32-byte string and process it as specified in
 *   Elliptic Curves for Security [RFC7748] §5.
 *
 * - Curve448 (PSA_ECC_FAMILY_MONTGOMERY, 448 bits):
 *   draw a 56-byte string and process it as specified in [RFC7748] §5.
 *
 * Note: Function allocates memory for *data buffer, so given *data should be
 *       always NULL.
 */
```

