# API Constraints: EVP_PKEY_verify (OpenSSL 3.5.5)

Source version: `/home/wen/work/clean_sources/openssl-3.5.5`

## API

- API/function name: `EVP_PKEY_verify`
- Header declaration: `include/openssl/evp.h`
- Implementation file: `crypto/evp/signature.c`
- Manpage: `doc/man3/EVP_PKEY_verify.pod`
- Signature:

```c
int EVP_PKEY_verify(EVP_PKEY_CTX *ctx,
    const unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);
```

## Semantics

- Verifies a signature over data that is already in the form expected by the key/signature algorithm.
- Requires an initialized `EVP_PKEY_CTX`, normally via `EVP_PKEY_verify_init`.
- For digest-based verification, `EVP_DigestVerify*` is often preferred.

## Return Value Semantics

- Returns `1` on successful verification.
- Returns `0` when the signature does not verify.
- Returns a negative value for errors; `-2` can indicate operation not supported.

## Object and Buffer Constraints

- `EVP_PKEY_CTX` and `EVP_PKEY` are opaque. Harnesses must not access internal fields.
- `sig` and `tbs` are caller-owned input buffers.
- The API does not write into caller output buffers.

## Adapter Generation Notes

- Uses caller-provided output buffer: no.
- Exposes explicit output length: input lengths only (`siglen`, `tbslen`).
- Good oracle: distinguish `1`, `0`, and negative errors.
- Useful for direct RSA-PSS verify harnesses after configuring padding and digest parameters on `EVP_PKEY_CTX`.

## Vulnerability-Pattern Migration Notes

- Candidate for signature verification migration from `mbedtls_pk_verify_ext`.
- Generic key and provider-backed contexts are opaque; harnesses should rely only on public EVP controls.

## Related Tests or Examples Found Locally

- `test/evp_extra_test.c`: direct calls around lines 1661 and 1738.
- `test/evp_test.c`: direct call around line 2939.
- `test/slh_dsa_test.c`: direct calls around lines 231, 421, 508, and 509.
- Demo: `demos/signature/rsa_pss_direct.c` uses `EVP_PKEY_verify`.
- Manpage `doc/man3/EVP_PKEY_verify.pod` includes examples.
