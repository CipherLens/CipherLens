# API Constraints: BN_signed_bn2bin (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `BN_signed_bn2bin`
- Header declaration: `include/openssl/bn.h`
- Implementation file: `crypto/bn/bn_lib.c`
- Manpage: `doc/man3/BN_bn2bin.pod`
- Signature:

```c
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
```

## Semantics

- Converts `a` to big-endian signed two's-complement form and writes to `to`.
- `to` is a caller-provided output buffer.
- `tolen` is the explicit output length.
- Pads with `0x00` for positive numbers or `0xff` for negative numbers.
- May require `BN_num_bytes(a) + 1` bytes for sign representation.

## Return Value Semantics

- Returns the number of bytes written on success, normally `tolen`.
- Returns `-1` on error, including negative `tolen` or insufficient size.

## Object and Buffer Ownership Constraints

- `BIGNUM` is opaque in OpenSSL 3.x. Harnesses must not access `a->d`, `a->top`, `a->neg`, `a->mpi`, or any `a->...` internal fields.
- Set negative values only through public APIs, for example `BN_set_negative(bn, 1)`.
- The output buffer is caller-owned and written by OpenSSL.

## Adapter Generation Notes

- Uses caller-provided output buffer: yes.
- Exposes explicit output length: yes, `tolen`.
- Writes into caller buffer: yes.
- Supports negative-number binary sign representation: yes, signed two's-complement.

## Vulnerability-Pattern Migration Notes

- Stronger candidate than `BN_bn2binpad` for negative-number serialization migration because it preserves signed output semantics.
- It is binary signed representation, not textual sign-plus-digits.

## Related Tests or Examples Found Locally

- `test/bntest.c`: direct `BN_signed_bn2bin` / `BN_signed_bin2bn` tests around lines 1943 and 1948.
- Manpage `doc/man3/BN_bn2bin.pod` documents signed extension and insufficient-size error behavior.
