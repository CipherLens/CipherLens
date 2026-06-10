# secure_heap_init_failed_then_query_candidate_validation

## Source

This sprint validates the candidate discovered in `secure_heap_state_lifecycle_pattern_expansion_v1`:

```text
secure_heap_exp_0003_new_state_init_failed_then_used
```

It is not one of the original `OPENSSL-ISSUE-28669` seed cases. The original seed cases are pre-init query and post-done query. This candidate is failed-init then query.

## Minimal Reproducers

- `minimal_reproducer/init_failed_then_used.c`
- `minimal_reproducer/pre_init_used_seed_control.c`
- `minimal_reproducer/initialized_then_used_safe_control.c`

## Result

- `init_failed_then_used`: `CRYPTO_secure_malloc_init(16, 16)=0`, then `CRYPTO_secure_used()` crashes with `SIGSEGV` / exit `139`.
- `pre_init_used_seed_control`: seed control crashes with `SIGSEGV` / exit `139`.
- `initialized_then_used_safe_control`: exits normally.

## Debug Evidence

GDB confirms the candidate reaches:

```text
___pthread_rwlock_rdlock(rwlock=0x0)
CRYPTO_THREAD_read_lock(lock=0x0)
CRYPTO_secure_used()
```

Valgrind is unavailable in this environment. ASAN/UBSAN evidence is left as a TODO because this sprint does not rebuild OpenSSL.

## API Contract

The local API contract is ambiguous for `CRYPTO_secure_used()` after failed `CRYPTO_secure_malloc_init()`. This should be confirmed manually or upstream before any stronger claim.

## Version Matrix

Only OpenSSL 3.5.5 is available locally, so the version matrix is `limited_single_version`.

## Classification

```text
validated_new_state_candidate
current_version_robustness_candidate
```

This is not a confirmed vulnerability and not a CVE claim.

## Upstream Suitability

It is suitable for a cautious upstream question framed as robustness/API-contract clarification, not as a vulnerability report.
