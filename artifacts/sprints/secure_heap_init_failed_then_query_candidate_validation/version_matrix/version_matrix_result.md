# Version Matrix Result

Available local versions:

```text
${CLEAN_SOURCES_ROOT}/openssl-3.5.5
```

The matrix is therefore:

```text
version_matrix_status: limited_single_version
```

## OpenSSL 3.5.5

- `init_failed_then_used`: exit `139`, `SIGSEGV`, validated new-state candidate.
- `pre_init_used_seed_control`: exit `139`, `SIGSEGV`, non-novel seed reproduction.
- `initialized_then_used_safe_control`: exit `0`, normal defined behavior.

Classification:

```text
current_version_robustness_candidate
```

No regression or new affected version claim can be made without additional local versions or upstream fixed-version evidence.
