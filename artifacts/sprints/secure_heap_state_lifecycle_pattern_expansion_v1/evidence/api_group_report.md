# Secure Heap API Group Report

Source inspection used `${CLEAN_SOURCES_ROOT}/openssl-*` and recorded raw hits in:

```text
artifacts/sprints/secure_heap_state_lifecycle_pattern_expansion_v1/evidence/secure_heap_api_source_hits.txt
```

The local available OpenSSL source tree is:

```text
${CLEAN_SOURCES_ROOT}/openssl-3.5.5
```

## API Group

- `CRYPTO_secure_malloc_init`: lifecycle init; declared in `include/openssl/crypto.h`, implemented in `crypto/mem_sec.c`.
- `CRYPTO_secure_malloc_done`: lifecycle done; releases secure heap and frees the lock when `secure_mem_used == 0`.
- `CRYPTO_secure_malloc_initialized`: lifecycle check; returns whether secure heap is available.
- `CRYPTO_secure_used`: lifecycle query; reads `secure_mem_used` under `sec_malloc_lock` and is the seed crash API.
- `CRYPTO_secure_allocated`: lifecycle query; has an explicit `!secure_mem_initialized` guard.
- `OPENSSL_secure_malloc`: lifecycle alloc; documented to fall back to `OPENSSL_malloc()` if secure heap is not initialized.
- `OPENSSL_secure_zalloc`: lifecycle alloc; zeroing allocation path.
- `OPENSSL_secure_free`: lifecycle free; documented as equivalent to `OPENSSL_free()` if secure heap is not initialized.

## Expansion Use

All required APIs exist in headers and are usable in expansion. The important contrast is that several APIs have explicit pre-init fallback or guard semantics, while `CRYPTO_secure_used()` takes a lock without an explicit initialization guard in the inspected implementation.
