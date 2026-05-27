# Bignum Template: mpi_sub_abs limb-boundary canary

## Source PoC

`poc_mpi_sub_abs_min.c`

## Source API

`mbedtls_mpi_sub_abs`

## Vulnerability Pattern

The source PoC constructs `A` as a small integer and `B` as a larger integer, manually allocates `X` with a small limb count, places canary bytes after `X->p`, and calls `mbedtls_mpi_sub_abs(&X, &A, &B)`.

If the implementation writes beyond the manually allocated `X->p` buffer, the canary bytes are corrupted.

## Key Mutation Points

- `[A_VALUE]`: small value for A
- `[B_VALUE]`: large value for B
- `[A_BASE]`: radix for A
- `[B_BASE]`: radix for B
- `[X_LIMB_COUNT]`: manually allocated limb count for X
- `[CANARY_SIZE]`: canary region size

## Oracle

- Canary corrupted: possible OOB write
- `MBEDTLS_ERR_MPI_NEGATIVE_VALUE` with intact canary: expected safe rejection
- Input parsing failure: harness construction issue
- ASAN/UBSAN crash: memory safety issue requiring triage

## Cross-library Candidate

`tmpl_openssl.c` maps the abstract operation to OpenSSL `BN_usub`. This is only a candidate migration harness. It does not assume OpenSSL has the same vulnerability path.
