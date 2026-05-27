# API Constraints: mbedtls_pem_read_buffer (mbedTLS 4.1.0)

Source version: `/home/wen/work/clean_sources/mbedtls-4.1.0`

## API

- API/function name: `mbedtls_pem_read_buffer`
- Header declaration: `tf-psa-crypto/include/mbedtls/pem.h`
- Implementation file: `tf-psa-crypto/utilities/pem.c`
- Signature:

```c
int mbedtls_pem_read_buffer(mbedtls_pem_context *ctx,
                            const char *header,
                            const char *footer,
                            const unsigned char *data,
                            const unsigned char *pwd,
                            size_t pwdlen,
                            size_t *use_len);
```

## Parameter Semantics

- `ctx`: output PEM context. It must be non-NULL and must later be released with `mbedtls_pem_free()`.
- `header`, `footer`: ASCII PEM boundary strings searched with `strstr()`.
- `data`: null-terminated PEM text input. Callers that wrap this API avoid calling it on non-null-terminated buffers.
- `pwd`, `pwdlen`: optional password bytes for encrypted PEM input.
- `use_len`: caller-visible consumed length, set to the end of the footer plus optional newline.

## Return Value Semantics

- `0`: success; `ctx->buf` and `ctx->buflen` contain decoded binary data.
- `MBEDTLS_ERR_PEM_BAD_INPUT_DATA`: invalid context or empty decoded data.
- `MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT`: missing PEM boundaries.
- `MBEDTLS_ERR_PEM_INVALID_DATA`: malformed encrypted PEM data or invalid decoded data.
- `MBEDTLS_ERR_PEM_PASSWORD_REQUIRED` / `MBEDTLS_ERR_PEM_PASSWORD_MISMATCH`: encrypted PEM password failures.
- `MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG`, `MBEDTLS_ERR_PEM_INVALID_ENC_IV`, `MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE`, `MBEDTLS_ERR_PEM_ALLOC_FAILED`, or wrapped base64/AES errors may be returned.

## Ownership and Buffer Constraints

- The decoded buffer is allocated by mbedTLS and owned by `ctx` on success.
- The decoded buffer remains valid until `ctx` is modified or `mbedtls_pem_free()` is called.
- On error, temporary decoded buffers are zeroized and freed.
- The API hides the decoded buffer allocation boundary from the caller, but sanitizer oracles can still observe internal under/over-reads.

## Harness Generation Notes

- For `MBEDTLS-POC-0011`, use an encrypted PEM header such as `Proc-Type: 4,ENCRYPTED` plus `DEK-Info: AES-128-CBC,...`.
- Keep PEM input null-terminated.
- Observe `ret`, `use_len`, and ASAN output.
- The migration-relevant path is encrypted PEM base64 decode -> AES-CBC decrypt -> PKCS padding check.

## Vulnerability-Pattern Migration Notes

- Relevant to `MBEDTLS-POC-0011`.
- The source bug path is a malformed encrypted PEM body that can lead to a zero-length decoded/decrypted buffer entering `pem_check_pkcs_padding()`.
- A good target candidate should preserve armored text parsing, encrypted PEM handling, base64-to-binary decoding, padding validation, and observable invalid-data or sanitizer behavior.

## Related Tests or Examples Found Locally

- `tf-psa-crypto/tests/suites/test_suite_pem.function`: direct `mbedtls_pem_read_buffer()` harness.
- `tf-psa-crypto/tests/suites/test_suite_pem.data`: malformed encrypted AES-128-CBC PEM cases, including empty ciphertext and short base64 bodies.
- `tf-psa-crypto/extras/pkparse.c`: `mbedtls_pk_parse_key()` uses `mbedtls_pem_read_buffer()` after checking PEM input is null-terminated.
- `library/x509_crt.c`, `library/x509_crl.c`, `library/x509_csr.c`: certificate/CRL/CSR PEM parsing wrappers call this API.
