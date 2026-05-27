# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/ecp_curves_new.c
Knowledge type: api_constraints

## Snippet 1

```c
};

/*
 * Specialized function for creating the Curve25519 group
 */
static int ecp_use_curve25519(mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve25519_a24));

    ecp_mpi_load(&grp->P, curve25519_p, sizeof(curve25519_p));

    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    ecp_mpi_load(&grp->N, curve25519_n, sizeof(curve25519_n));

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 9));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* Actually, the required msb for private keys */
    grp->nbits = 254;

cleanup:
```

## Snippet 2

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve25519_a24));

    ecp_mpi_load(&grp->P, curve25519_p, sizeof(curve25519_p));

    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    ecp_mpi_load(&grp->N, curve25519_n, sizeof(curve25519_n));

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 9));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* Actually, the required msb for private keys */
    grp->nbits = 254;

cleanup:
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
/* Constants used by ecp_use_curve448() */
```

## Snippet 3

```c
ecp_mpi_load(&grp->P, curve25519_p, sizeof(curve25519_p));

    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    ecp_mpi_load(&grp->N, curve25519_n, sizeof(curve25519_n));

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 9));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* Actually, the required msb for private keys */
    grp->nbits = 254;

cleanup:
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE25519_ENABLED */

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
/* Constants used by ecp_use_curve448() */
static const mbedtls_mpi_sint curve448_a24 = 0x98AA;
```

## Snippet 4

```c
};

/*
 * Specialized function for creating the Curve448 group
 */
static int ecp_use_curve448(mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    ecp_mpi_load(&grp->P, curve448_p, sizeof(curve448_p));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    ecp_mpi_load(&grp->N, curve448_n, sizeof(curve448_n));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    if (ret != 0) {
```

## Snippet 5

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    ecp_mpi_load(&grp->P, curve448_p, sizeof(curve448_p));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    ecp_mpi_load(&grp->N, curve448_n, sizeof(curve448_n));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */
```

## Snippet 6

```c
/* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    ecp_mpi_load(&grp->P, curve448_p, sizeof(curve448_p));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    ecp_mpi_load(&grp->N, curve448_n, sizeof(curve448_n));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

/*
```

## Snippet 7

```c
/* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    ecp_mpi_load(&grp->P, curve448_p, sizeof(curve448_p));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    ecp_mpi_load(&grp->N, curve448_n, sizeof(curve448_n));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

/*
 * Set a group using well-known domain parameters
```

