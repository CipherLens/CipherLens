# Version Matrix

Available local OpenSSL versions:

```text
openssl-3.5.5
```

No new OpenSSL versions were downloaded.

## openssl-3.5.5

Version:

```text
OpenSSL 3.5.5 27 Jan 2026
```

Results:

| case | compile | exit | signal | verdict |
| --- | --- | ---: | ---: | --- |
| `pre_init_used_only` | ok | 139 | 11 | `crash_candidate` |
| `done_then_used` | ok | 139 | 11 | `crash_candidate` |
| `initialized_then_used_control` | ok | 0 | none | `normal_defined_behavior` |

Notes:

- `done_then_used` printed `CRYPTO_secure_malloc_init returned 1` and `CRYPTO_secure_malloc_done returned 1` before crashing.
- The initialized control printed `CRYPTO_secure_used returned 0` and exited normally.

## Conclusion

The only locally available version reproduces both crash cases while preserving
the initialized safe control. This strengthens the current
`robustness_hardening_candidate` assessment. It is not enough to call this a
confirmed vulnerability until the API contract is manually confirmed.
