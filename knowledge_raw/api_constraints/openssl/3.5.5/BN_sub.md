# API Constraints: BN_sub (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `BN_sub`
- Header declaration: `include/openssl/bn.h`
- Implementation file: `crypto/bn/bn_add.c`
- Manpage: `doc/man3/BN_add.pod`
- Signature:

```c
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
```

## Semantics

- Computes signed BIGNUM subtraction `r = a - b`.
- `r` may be the same `BIGNUM` as `a` or `b`.
- Implementation dispatches to `BN_uadd` or `BN_usub` based on signs and magnitude.

## Return Value Semantics

- Returns `1` on success.
- Returns `0` on error.

## Object and Buffer Ownership Constraints

- `BIGNUM` is opaque in OpenSSL 3.x. Harnesses must not access any internal `BIGNUM` fields.
- Result storage is managed inside OpenSSL; caller cannot directly place a canary after internal limbs.
- Use public APIs to create, set, compare, serialize, and free BIGNUMs.

## Adapter Generation Notes

- Uses caller-provided output buffer: no.
- Exposes explicit output length: no.
- Writes into caller buffer: no; writes into OpenSSL-managed `BIGNUM *r`.
- Good oracles are return value and public serialization/comparison results.

## Vulnerability-Pattern Migration Notes

- Functionally related to bignum subtraction, but weak for `MBEDTLS-POC-0002` because it does not preserve output limb boundary control.

## Related Tests or Examples Found Locally

- `test/bntest.c`: direct `BN_sub` tests around lines 262, 264, 307, 1232, 1234, 1250, 1253, 1256, and 1259.
- Many internal OpenSSL modules call `BN_sub` for arithmetic.
