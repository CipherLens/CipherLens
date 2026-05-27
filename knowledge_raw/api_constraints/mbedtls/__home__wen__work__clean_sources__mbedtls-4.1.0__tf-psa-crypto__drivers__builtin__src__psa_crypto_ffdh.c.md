# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/psa_crypto_ffdh.c
Knowledge type: api_constraints

## Snippet 1

```c
if (key_buffer_size > data_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(data, key_buffer, key_buffer_size);
        memset(data + key_buffer_size, 0,
               data_size - key_buffer_size);
        *data_length = key_buffer_size;
        return PSA_SUCCESS;
    }

    mbedtls_mpi_init(&GX); mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&P);

    size_t key_len = PSA_BITS_TO_BYTES(attributes->bits);
    if (key_len > data_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    status = mbedtls_psa_ffdh_set_prime_generator(key_len, &P, &G);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));
```

## Snippet 2

```c
return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        memcpy(data, key_buffer, key_buffer_size);
        memset(data + key_buffer_size, 0,
               data_size - key_buffer_size);
        *data_length = key_buffer_size;
        return PSA_SUCCESS;
    }

    mbedtls_mpi_init(&GX); mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&P);

    size_t key_len = PSA_BITS_TO_BYTES(attributes->bits);
    if (key_len > data_size) {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    status = mbedtls_psa_ffdh_set_prime_generator(key_len, &P, &G);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL));
```

## Snippet 3

```c
status = mbedtls_psa_ffdh_set_prime_generator(key_len, &P, &G);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&GX, data, key_len));

    *data_length = key_len;

    ret = 0;
cleanup:
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GX);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT ||
          MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY */
```

## Snippet 4

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&GX, data, key_len));

    *data_length = key_len;

    ret = 0;
cleanup:
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GX);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT ||
          MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_ffdh_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    mbedtls_mpi X, P;
```

## Snippet 5

```c
key_buffer_size));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&GX, &G, &X, &P, NULL));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&GX, data, key_len));

    *data_length = key_len;

    ret = 0;
cleanup:
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GX);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_EXPORT ||
          MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_ffdh_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    mbedtls_mpi X, P;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
```

## Snippet 6

```c
MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_PUBLIC_KEY */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE)
psa_status_t mbedtls_psa_ffdh_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    mbedtls_mpi X, P;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_init(&P); mbedtls_mpi_init(&X);
    (void) attributes;

    status = mbedtls_psa_ffdh_set_prime_generator(key_buffer_size, &P, NULL);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* RFC7919: Traditional finite field Diffie-Hellman has each peer choose their
        secret exponent from the range [2, P-2].
        Select random value in range [3, P-1] and decrease it by 1. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_random(&X, 3, &P, mbedtls_psa_get_random,
                                       MBEDTLS_PSA_RANDOM_STATE));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&X, &X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&X, key_buffer, key_buffer_size));
    *key_buffer_length = key_buffer_size;
```

## Snippet 7

```c
if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* RFC7919: Traditional finite field Diffie-Hellman has each peer choose their
        secret exponent from the range [2, P-2].
        Select random value in range [3, P-1] and decrease it by 1. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_random(&X, 3, &P, mbedtls_psa_get_random,
                                       MBEDTLS_PSA_RANDOM_STATE));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&X, &X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&X, key_buffer, key_buffer_size));
    *key_buffer_length = key_buffer_size;

cleanup:
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&X);
    if (status == PSA_SUCCESS && ret != 0) {
        return mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT)
psa_status_t mbedtls_psa_ffdh_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
```

## Snippet 8

```c
/* RFC7919: Traditional finite field Diffie-Hellman has each peer choose their
        secret exponent from the range [2, P-2].
        Select random value in range [3, P-1] and decrease it by 1. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_random(&X, 3, &P, mbedtls_psa_get_random,
                                       MBEDTLS_PSA_RANDOM_STATE));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&X, &X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&X, key_buffer, key_buffer_size));
    *key_buffer_length = key_buffer_size;

cleanup:
    mbedtls_mpi_free(&P); mbedtls_mpi_free(&X);
    if (status == PSA_SUCCESS && ret != 0) {
        return mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_GENERATE */

#if defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_DH_KEY_PAIR_IMPORT)
psa_status_t mbedtls_psa_ffdh_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data, size_t data_length,
    uint8_t *key_buffer, size_t key_buffer_size,
    size_t *key_buffer_length, size_t *bits)
{
    (void) attributes;
```

## Snippet 9

```c
if (peer_key_length != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* This has been checked by the core, but keep a local check too. */
    if (calculated_shared_secret_size > shared_secret_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GY);
    mbedtls_mpi_init(&K);

    status = mbedtls_psa_ffdh_set_prime_generator(
        PSA_BITS_TO_BYTES(attributes->bits), &P, NULL);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&GY, peer_key,
                                            peer_key_length));

    /* RFC 7919 5.1: validate the peer's public key: 1 < GY < P-1
     *
     * This check is sufficient to ensure GY is not of low order, because we're
     * using a safe prime (that is, q = (p-1) / 2 is also prime), so the only
```

## Snippet 10

```c
if (peer_key_length != key_buffer_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* This has been checked by the core, but keep a local check too. */
    if (calculated_shared_secret_size > shared_secret_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GY);
    mbedtls_mpi_init(&K);

    status = mbedtls_psa_ffdh_set_prime_generator(
        PSA_BITS_TO_BYTES(attributes->bits), &P, NULL);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&GY, peer_key,
                                            peer_key_length));

    /* RFC 7919 5.1: validate the peer's public key: 1 < GY < P-1
     *
     * This check is sufficient to ensure GY is not of low order, because we're
     * using a safe prime (that is, q = (p-1) / 2 is also prime), so the only
     * group elements of low order are 1 and p-1. (Obviously we also want to
```

## Snippet 11

```c
return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* This has been checked by the core, but keep a local check too. */
    if (calculated_shared_secret_size > shared_secret_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&GY);
    mbedtls_mpi_init(&K);

    status = mbedtls_psa_ffdh_set_prime_generator(
        PSA_BITS_TO_BYTES(attributes->bits), &P, NULL);

    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&GY, peer_key,
                                            peer_key_length));

    /* RFC 7919 5.1: validate the peer's public key: 1 < GY < P-1
     *
     * This check is sufficient to ensure GY is not of low order, because we're
     * using a safe prime (that is, q = (p-1) / 2 is also prime), so the only
     * group elements of low order are 1 and p-1. (Obviously we also want to
     * exclude 0 that is not a group element, and values >= p as they are not
```

## Snippet 12

```c
* adversary). Checking before is cleaner in terms of side channel analysis,
     * as we haven't loaded our secret yet, so no worries about branches.
     *
     * Use X as a temporary, since we haven't loaded it yet.
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&X, &P, 1)); // x = p - 1
    if (mbedtls_mpi_cmp_mpi(&GY, &X) >= 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&X, 1)); // x = 1
    if (mbedtls_mpi_cmp_mpi(&GY, &X) <= 0) {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    /* Calculate shared secret public key: K = G^(XY) mod P = GY^X mod P */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL));

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, shared_secret,
                                             calculated_shared_secret_size));

    *shared_secret_length = calculated_shared_secret_size;

    ret = 0;
```

## Snippet 13

```c
status = PSA_ERROR_INVALID_ARGUMENT;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&X, key_buffer,
                                            key_buffer_size));

    /* Calculate shared secret public key: K = G^(XY) mod P = GY^X mod P */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL));

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, shared_secret,
                                             calculated_shared_secret_size));

    *shared_secret_length = calculated_shared_secret_size;

    ret = 0;

cleanup:
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&K);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
```

## Snippet 14

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&K, &GY, &X, &P, NULL));

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, shared_secret,
                                             calculated_shared_secret_size));

    *shared_secret_length = calculated_shared_secret_size;

    ret = 0;

cleanup:
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&K);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_FFDH */

#endif /* MBEDTLS_PSA_CRYPTO_C */
```

## Snippet 15

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&K, shared_secret,
                                             calculated_shared_secret_size));

    *shared_secret_length = calculated_shared_secret_size;

    ret = 0;

cleanup:
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&GY);
    mbedtls_mpi_free(&K);

    if (status == PSA_SUCCESS && ret != 0) {
        status = mbedtls_to_psa_error(ret);
    }

    return status;
}
#endif /* MBEDTLS_PSA_BUILTIN_ALG_FFDH */

#endif /* MBEDTLS_PSA_CRYPTO_C */
```

