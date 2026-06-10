# Next Stage Pattern Expansion Plan

`secure_heap_state_lifecycle_v1` is seed validation, not final discovery. The
next stage must perform same-family, cross-version, or cross-library analogous
lifecycle expansion.

## Route 1: OpenSSL Same-Family API Expansion

Expand from `CRYPTO_secure_used()` to related secure heap APIs:

```text
CRYPTO_secure_malloc_initialized
CRYPTO_secure_allocated
OPENSSL_secure_malloc
OPENSSL_secure_zalloc
OPENSSL_secure_free
CRYPTO_secure_malloc_done
```

State combinations:

```text
pre_init
initialized
init_failed
done
done_twice
done_then_query
done_then_free
done_then_alloc
reinit_after_done
query_after_failed_init
```

Goal: find new crash candidates or robustness hardening candidates not covered
by the original issue.

## Route 2: OpenSSL Cross-Version Expansion

Run a small core matrix against every available OpenSSL source/build:

```text
pre_init_used_only
done_then_used
initialized_then_used_control
done_twice
reinit_after_done
```

Goal: classify whether the behavior is historical reproduction, new affected
version candidate, regression candidate, or current-version hardening candidate.

## Route 3: Cross-Library Analogous Lifecycle Oracle

Do not force `CRYPTO_secure_used()` into an mbedTLS equivalent. Instead abstract
the behavior as:

```text
state_lifecycle_robustness_oracle
```

Candidate directions:

```text
mbedTLS PSA crypto lifecycle:
  psa_crypto_init before/after behavior
  finish after update/final
  update after finish
  free after failure
  reuse after free

Other libraries:
  Botan / wolfSSL / LibreSSL allocator, secure memory, and context lifecycle APIs
```

Goal: compare safe reject, defined return, permissive behavior, and crash across
state lifecycle boundaries.
