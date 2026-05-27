# OpenSSL PoC Artifact: issue_28669

## Source

- Issue: https://github.com/openssl/openssl/issues/28669
- Title: NULL rwlock dereference in CRYPTO_secure_used when secure heap is not initialized
- State: closed

## PoC Information

- PoC type: C_API+STACKTRACE
- Component: CRYPTO/MEM_SEC
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: None
- Quality: None

## Root Cause

None

## Critical APIs

- CRYPTO_secure_used

## Reproduction Command From JSON

['int main(){\n    // Call without initializing the secure heap\n    size_t u = CRYPTO_secure_used();\n    (void)u;\n    return 0;\n}']

## Notes

This artifact was generated from structured PoC JSON.

The local validation only proves that the PoC can be compiled and executed against the currently linked OpenSSL library.
Strict reproduction requires compiling and running against the original affected OpenSSL version.
