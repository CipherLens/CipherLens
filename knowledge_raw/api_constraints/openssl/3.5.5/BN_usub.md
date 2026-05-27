# API Constraints: BN_usub (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `BN_usub`
- Header declaration: `include/openssl/bn.h`
- Implementation file: `crypto/bn/bn_add.c`
- Manpage context: `doc/man3/BN_add.pod`
- Signature:

```c
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
```

## Semantics

- Performs unsigned subtraction of `b` from `a`.
- Implementation comment states `a` must be larger than `b`.
- Result is placed in `r`.
- `r` may alias inputs in normal BIGNUM arithmetic patterns.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on error.
- If `a < b`, implementation raises `BN_R_ARG2_LT_ARG3` and returns `0`.

## Object and Buffer Ownership Constraints

- `BIGNUM` is opaque in OpenSSL 3.x. Harnesses must not access `r->d`, `r->top`, `r->neg`, `a->...`, or `b->...`.
- OpenSSL manages internal limb allocation through public BN APIs.
- There is no caller-provided limb buffer and no explicit limb count parameter.

## Adapter Generation Notes

- Uses caller-provided output buffer: no.
- Exposes explicit output length: no.
- Writes into caller buffer: no; writes into `BIGNUM *r` through OpenSSL-managed allocation.
- Harnesses should observe return value and public BN serialization/comparison APIs.

## Vulnerability-Pattern Migration Notes

- Functionally related to `mbedtls_mpi_sub_abs`, but weak for automatic migration of output-limb-boundary patterns.
- Does not preserve manual `X->p`/`X->n` control or canary-after-limbs behavior.

## Related Tests or Examples Found Locally

- `test/bntest.c`: direct `BN_usub` tests around lines 1264, 1272, 1274, 1290, 1293, 1296, and 1299.
- Internal callers include `crypto/bn/bn_mont.c` and `crypto/bn/bn_gcd.c`.
