# API Constraints: mbedtls_pk_parse_key (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_pk_parse_key`
- Header declaration: `tf-psa-crypto/include/mbedtls/pk.h`
- Implementation file: `tf-psa-crypto/extras/pkparse.c`
- Signature:

```c
int mbedtls_pk_parse_key(mbedtls_pk_context *ctx,
                         const unsigned char *key,
                         size_t keylen,
                         const unsigned char *pwd,
                         size_t pwdlen);
```

## Parameter Semantics

- `ctx`: empty `mbedtls_pk_context` to populate.
- `key`: PEM or DER private key input. The documented contract says the buffer must contain the input exactly with no trailing material.
- `keylen`: input length; for PEM this includes the terminating null byte.
- `pwd`, `pwdlen`: optional password for encrypted private keys.

## Return Value Semantics

- `0`: private key parsed and checked.
- `MBEDTLS_ERR_PK_KEY_INVALID_FORMAT`: empty or unsupported key format.
- `MBEDTLS_ERR_PK_PASSWORD_MISMATCH` / `MBEDTLS_ERR_PK_PASSWORD_REQUIRED`: encrypted key password failures.
- PEM, PKCS#5, ASN.1, RSA, or EC parser errors can be propagated.

## Ownership and Buffer Constraints

- On success, key material is copied/imported into `ctx`; caller must later call `mbedtls_pk_free()`.
- PEM parsing allocates temporary decoded buffers owned by `mbedtls_pem_context` and freed before returning.
- On failed parser attempts, the function frees and reinitializes `ctx`.

## Harness Generation Notes

- Initialize `mbedtls_pk_context`, call `mbedtls_pk_parse_key()`, observe return code, then free the context.
- To isolate RSA top-level trailing-garbage behavior for `MBEDTLS-POC-0020`, direct internal RSA parser calls may be more precise, but this public API should be recorded as the source-level public key parsing context.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0020`.
- Public key parsing documentation explicitly says no extra trailing material is allowed.
- Good target APIs should expose exact-input-consumed DER parsing and observable accept-vs-reject return behavior.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_pkparse.function`: direct `mbedtls_pk_parse_key()` and PKCS#8 parsing tests.
- `tf-psa-crypto/tests/suites/test_suite_pk.function`: direct `mbedtls_pk_parse_key()` tests and invalid-input checks.
- `programs/ssl/ssl_server.c`, `programs/ssl/dtls_server.c`, `programs/ssl/ssl_client2.c`: application examples.
