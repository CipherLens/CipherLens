# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/ecp_curves.c
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

    /* P = 2^255 - 19 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 255));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 19));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->N,
                                            curve25519_part_of_n, sizeof(curve25519_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 9));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);
```

## Snippet 2

```c
* Specialized function for creating the Curve25519 group
 */
static int ecp_use_curve25519(mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve25519_a24));

    /* P = 2^255 - 19 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 255));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 19));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->N,
                                            curve25519_part_of_n, sizeof(curve25519_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 9));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* Actually, the required msb for private keys */
    grp->nbits = 254;
```

## Snippet 3

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 19));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->N,
                                            curve25519_part_of_n, sizeof(curve25519_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

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

## Snippet 4

```c
grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->N,
                                            curve25519_part_of_n, sizeof(curve25519_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

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

## Snippet 5

```c
/* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&grp->N,
                                            curve25519_part_of_n, sizeof(curve25519_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

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
static const unsigned char curve448_part_of_n[] = {
```

## Snippet 6

```c
};

/*
 * Specialized function for creating the Curve448 group
 */
static int ecp_use_curve448(mbedtls_ecp_group *grp)
{
    mbedtls_mpi Ns;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi_init(&Ns);

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    /* P = 2^448 - 2^224 - 1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);
```

## Snippet 7

```c
* Specialized function for creating the Curve448 group
 */
static int ecp_use_curve448(mbedtls_ecp_group *grp)
{
    mbedtls_mpi Ns;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi_init(&Ns);

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    /* P = 2^448 - 2^224 - 1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
```

## Snippet 8

```c
{
    mbedtls_mpi Ns;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi_init(&Ns);

    /* Actually ( A + 2 ) / 4 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->A, curve448_a24));

    /* P = 2^448 - 2^224 - 1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Ns,
                                            curve448_part_of_n, sizeof(curve448_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&grp->N, &grp->N, &Ns));
```

## Snippet 9

```c
/* P = 2^448 - 2^224 - 1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Ns,
                                            curve448_part_of_n, sizeof(curve448_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&grp->N, &grp->N, &Ns));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    mbedtls_mpi_free(&Ns);
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }
```

## Snippet 10

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Ns,
                                            curve448_part_of_n, sizeof(curve448_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&grp->N, &grp->N, &Ns));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    mbedtls_mpi_free(&Ns);
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }
```

## Snippet 11

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 224));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 1));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* Y intentionally not set, since we use x/z coordinates.
     * This is used as a marker to identify Montgomery curves! */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.X, 5));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.Z, 1));
    mbedtls_mpi_free(&grp->G.Y);

    /* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Ns,
                                            curve448_part_of_n, sizeof(curve448_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&grp->N, &grp->N, &Ns));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    mbedtls_mpi_free(&Ns);
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
```

## Snippet 12

```c
/* N = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 446, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&Ns,
                                            curve448_part_of_n, sizeof(curve448_part_of_n)));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&grp->N, &grp->N, &Ns));

    /* Actually, the required msb for private keys */
    grp->nbits = 447;

cleanup:
    mbedtls_mpi_free(&Ns);
    if (ret != 0) {
        mbedtls_ecp_group_free(grp);
    }

    return ret;
}
#endif /* MBEDTLS_ECP_DP_CURVE448_ENABLED */

/*
 * Set a group using well-known domain parameters
 */
int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, mbedtls_ecp_group_id id)
{
    mbedtls_ecp_group_free(grp);

    mbedtls_ecp_group_init(grp);
```

