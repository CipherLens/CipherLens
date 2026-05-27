# API Constraints: mbedtls_pk_verify_ext (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_pk_verify_ext`
- Source file: `tf-psa-crypto/extras/pk.c`
- Declaration: `tf-psa-crypto/include/mbedtls/pk.h`
- Signature:

```c
int mbedtls_pk_verify_ext(mbedtls_pk_sigalg_t type,
                          mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len);
```

## Parameter Semantics

- `type`: signature algorithm to verify, for example `MBEDTLS_PK_SIGALG_RSA_PSS`.
- `ctx`: populated public-key context.
- `md_alg`: hash algorithm.
- `hash`/`hash_len`: digest to verify. If `md_alg != MBEDTLS_MD_NONE` or `hash_len != 0`, `hash` must not be NULL.
- `sig`/`sig_len`: signature buffer and length.

## Return Value Semantics

- `0`: signature is valid.
- `MBEDTLS_ERR_PK_BAD_INPUT_DATA`: invalid inputs or uninitialized `ctx->pk_info`.
- `MBEDTLS_ERR_PK_TYPE_MISMATCH`: context cannot be used for requested signature type.
- `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE`: unsupported feature, including non-RSA context for RSA-PSS path.
- `PSA_ERROR_INVALID_SIGNATURE` mapped through the PSA-to-mbedTLS error path can indicate invalid signature.

## Object Lifetime Constraints

- `ctx` must be initialized and populated before verification.
- Caller retains ownership of `hash` and `sig`; they are input buffers.
- No caller-provided output buffer is used.

## Harness Generation Notes

- Build or parse a key into `mbedtls_pk_context`, prepare digest and signature, then call `mbedtls_pk_verify_ext`.
- For RSA-PSS migration, ensure the selected mbedTLS 4.1.0 enum name is `MBEDTLS_PK_SIGALG_RSA_PSS`.
- Good oracles: return code, safe type rejection, no NULL dereference.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0003`.
- Current 4.1.0 source includes a guard before RSA-PSS-specific work: non-RSA contexts return `MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE`.
- Cross-library candidates should preserve generic/opaque key context dispatch and safe unsupported-type return behavior.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_pk.function`: direct calls around lines 812, 817, 899, 1129, 1363, 1526, 1561, 1620, 1624, and 1636.
- `tests/suites/test_suite_x509write.function`: direct use around line 43.
- Library callers: `library/x509_crt.c`, `library/pkcs7.c`, `library/ssl_tls12_client.c`, `library/ssl_tls12_server.c`, `library/ssl_tls13_generic.c`.
