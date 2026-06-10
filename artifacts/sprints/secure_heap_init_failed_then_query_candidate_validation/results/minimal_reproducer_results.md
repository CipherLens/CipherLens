# Minimal Reproducer Results

## Summary

- `init_failed_then_used`: compile ok, `CRYPTO_secure_malloc_init(16, 16)=0`, then `CRYPTO_secure_used()` causes exit `139` / `SIGSEGV`.
- `pre_init_used_seed_control`: compile ok, seed control causes exit `139` / `SIGSEGV`.
- `initialized_then_used_safe_control`: compile ok, `CRYPTO_secure_malloc_init(4096, 32)=1`, `CRYPTO_secure_used()=0`, exits `0`.

## Verdict

```text
validation_status: validated_new_state_candidate
```

The minimal form reproduces the expansion candidate while the initialized control exits normally.
