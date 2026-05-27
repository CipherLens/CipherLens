# API Constraints: BN_bn2binpad (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `BN_bn2binpad`
- Header declaration: `include/openssl/bn.h`
- Implementation file: `crypto/bn/bn_lib.c`
- Manpage: `doc/man3/BN_bn2bin.pod`
- Signature:

```c
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
```

## Semantics

- Converts the absolute value of `a` to big-endian binary and writes to `to`.
- `to` is a caller-provided output buffer.
- `tolen` is the explicit output buffer length.
- Pads with leading zero bytes if the number is smaller than `tolen`.
- Returns an error if `tolen` is less than `BN_num_bytes(a)`.

## Return Value Semantics

- Returns `tolen` on success.
- Returns `-1` on error, including negative `tolen` or insufficient output size.

## Object and Buffer Ownership Constraints

- `BIGNUM` is opaque in OpenSSL 3.x. Harnesses must not access `a->d`, `a->top`, `a->neg`, or any `a->...` internal fields.
- Allocate/free BIGNUMs through public APIs such as `BN_new`, `BN_free`, `BN_clear_free`, `BN_bin2bn`, `BN_dec2bn`, `BN_hex2bn`, `BN_set_word`, and `BN_set_negative`.
- The output buffer `to` is caller-owned and written by OpenSSL.

## Adapter Generation Notes

- Uses caller-provided output buffer: yes.
- Exposes explicit output length: yes, `tolen`.
- Writes into caller buffer: yes.
- Sign handling: serializes absolute value only; negative sign is not encoded.

## Vulnerability-Pattern Migration Notes

- Good candidate for caller-buffer boundary migration from `mbedtls_mpi_write_string`, but it does not preserve textual radix or sign-byte semantics.
- Better for binary buffer-boundary patterns than negative string-sign patterns.

## Related Tests or Examples Found Locally

- `test/bntest.c`: direct `BN_bn2binpad` tests around lines 1821, 1824, 1840, 1843, 1846, 1850, and 1855.
- Internal callers include `crypto/rsa/rsa_ossl.c`, `crypto/dh/dh_key.c`, `crypto/sm2/*`, and providers.
