# Version Matrix Result

## Scope

Only local OpenSSL source trees under `${CLEAN_SOURCES_ROOT}` were used. The available version list contains:

```text
${CLEAN_SOURCES_ROOT}/openssl-3.5.5
```

Therefore this is a `limited_single_version` matrix, not a regression matrix.

## OpenSSL 3.5.5

The expansion run covered the required core states:

- `pre_init_used_only`: crash candidate, non-novel seed reproduction, `SIGSEGV` / exit `139`.
- `done_then_used`: crash candidate, non-novel seed reproduction, `SIGSEGV` / exit `139`.
- `initialized_control`: normal defined behavior.
- `done_twice`: normal defined behavior.
- `reinit_after_done`: normal defined behavior.

It also covered `init_failed_then_query`, which produced a non-seed crash candidate and is classified as:

```text
new_state_combination_candidate
```

## Classification

```text
current_version_robustness_candidate
limited_single_version
```

No regression candidate can be claimed because no fixed version or multi-version comparison was available locally.
