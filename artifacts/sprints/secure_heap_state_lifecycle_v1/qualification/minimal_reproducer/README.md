# Minimal Reproducers

These files are minimized OpenSSL API reproducers for
`OPENSSL-ISSUE-28669`. They do not include the framework crash wrapper and do
not hide crashes.

## Files

- `pre_init_used_only.c`: calls `CRYPTO_secure_used()` before secure heap initialization.
- `done_then_used.c`: initializes secure heap, calls `CRYPTO_secure_malloc_done()`, then calls `CRYPTO_secure_used()`.
- `initialized_then_used_control.c`: initializes secure heap, calls `CRYPTO_secure_used()`, then releases the heap.

## Compile

```bash
gcc pre_init_used_only.c -o build/pre_init_used_only \
  -I"$CLEAN_SOURCES_ROOT/openssl-3.5.5/include" \
  -L"$CLEAN_SOURCES_ROOT/openssl-3.5.5" \
  -lcrypto
```

Repeat for the other `.c` files.

## Run

```bash
./build/pre_init_used_only
./build/done_then_used
./build/initialized_then_used_control
```

Expected local behavior with `openssl-3.5.5`:

- `pre_init_used_only`: SIGSEGV / exit 139.
- `done_then_used`: SIGSEGV / exit 139 after init/done succeeds.
- `initialized_then_used_control`: exits 0 and prints a defined used value.

This expected behavior is a crash-candidate signal, not a confirmed
vulnerability claim.
