# API Contract: init failure then `CRYPTO_secure_used()`

Local docs describe `CRYPTO_secure_malloc_init()` return values and `CRYPTO_secure_malloc_initialized()` as an availability check. They also state that `CRYPTO_secure_used()` returns the number of bytes allocated in the secure heap.

However, the inspected docs do not explicitly state whether callers may or may not call `CRYPTO_secure_used()` after `CRYPTO_secure_malloc_init()` fails.

```text
contract_status: ambiguous
```

This ambiguity must not be converted directly into a vulnerability claim. The correct next step is manual upstream/API contract confirmation.
