# EVP_MAC_init Contract Notes

Source checked locally only. No public network access was used.

## Local evidence

- Source declaration: `/home/wen/work/install-openssl-3.5.5-asan/include/openssl/evp.h` declares `int EVP_MAC_init(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]);`.
- Manpage source: `/home/wen/work/openssl-3.5.5-asan-src/doc/man3/EVP_MAC.pod`.
- Implementation: `/home/wen/work/openssl-3.5.5-asan-src/crypto/evp/mac_lib.c`.

## Contract interpretation

- `EVP_MAC_CTX_new()` creates a context for a fetched MAC. The documentation says the created context can then be used with the other functions.
- The documentation explicitly states `EVP_MAC_CTX_free(NULL)` is a no-op, but does not state that `EVP_MAC_init(NULL, ...)` is accepted or safely rejected.
- `EVP_MAC_init()` describes setting up the underlying context `ctx`; it assumes a usable `EVP_MAC_CTX`.
- The implementation dereferences `ctx->meth` at `mac_lib.c:118`, so NULL ctx reaches OpenSSL internals before a NULL guard.
- Valid context + NULL key with zero key length returned error without sanitizer for HMAC/SHA256 in this triage harness. The documentation says if `key` is NULL, the key must be set via params or separately; this HMAC case did not provide a key parameter.
- Valid context + NULL key with nonzero key length returned error without sanitizer; this is treated as a contract-boundary observation, not a sanitizer candidate.

## Conclusion

`EVP_MAC_init(NULL, ...)` is best treated as invalid API use / contract-boundary hardening observation in the default campaign. It should not be promoted as a sanitizer candidate unless a future rule explicitly tracks NULL ctx hardening separately.
