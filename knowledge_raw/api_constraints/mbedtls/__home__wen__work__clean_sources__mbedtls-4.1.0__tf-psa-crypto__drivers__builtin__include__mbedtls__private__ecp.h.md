# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/include/mbedtls/private/ecp.h
Knowledge type: api_constraints

## Snippet 1

```c
* For Short Weierstrass, this subgroup is the whole curve, and its
 * cardinality is denoted by \p N. Our code requires that \p N is an
 * odd prime as mbedtls_ecp_mul() requires an odd number, and
 * mbedtls_ecdsa_sign() requires that it is prime for blinding purposes.
 *
 * The default implementation only initializes \p A without setting it to the
 * authentic value for curves with <code>A = -3</code>(SECP256R1, etc), in which
 * case you need to load \p A by yourself when using domain parameters directly,
 * for example:
 * \code
 * mbedtls_mpi_init(&A);
 * mbedtls_ecp_group_init(&grp);
 * CHECK_RETURN(mbedtls_ecp_group_load(&grp, grp_id));
 * if (mbedtls_ecp_group_a_is_minus_3(&grp)) {
 *     CHECK_RETURN(mbedtls_mpi_sub_int(&A, &grp.P, 3));
 * } else {
 *     CHECK_RETURN(mbedtls_mpi_copy(&A, &grp.A));
 * }
 *
 * do_something_with_a(&A);
 *
 * cleanup:
 * mbedtls_mpi_free(&A);
 * mbedtls_ecp_group_free(&grp);
 * \endcode
 *
 * For Montgomery curves, we do not store \p A, but <code>(A + 2) / 4</code>,
 * which is the quantity used in the formulas. Additionally, \p nbits is
```

## Snippet 2

```c
* CHECK_RETURN(mbedtls_ecp_group_load(&grp, grp_id));
 * if (mbedtls_ecp_group_a_is_minus_3(&grp)) {
 *     CHECK_RETURN(mbedtls_mpi_sub_int(&A, &grp.P, 3));
 * } else {
 *     CHECK_RETURN(mbedtls_mpi_copy(&A, &grp.A));
 * }
 *
 * do_something_with_a(&A);
 *
 * cleanup:
 * mbedtls_mpi_free(&A);
 * mbedtls_ecp_group_free(&grp);
 * \endcode
 *
 * For Montgomery curves, we do not store \p A, but <code>(A + 2) / 4</code>,
 * which is the quantity used in the formulas. Additionally, \p nbits is
 * not the size of \p N but the required size for private keys.
 *
 * If \p modp is NULL, reduction modulo \p P is done using a generic algorithm.
 * Otherwise, \p modp must point to a function that takes an \p mbedtls_mpi in the
 * range of <code>0..2^(2*pbits)-1</code>, and transforms it in-place to an integer
 * which is congruent mod \p P to the given MPI, and is close enough to \p pbits
 * in size, so that it may be efficiently brought in the 0..P-1 range by a few
 * additions or subtractions. Therefore, it is only an approximate modular
 * reduction. It must return 0 on success and non-zero on failure.
 *
 * \note        Alternative implementations of the ECP module must obey the
 *              following constraints.
```

