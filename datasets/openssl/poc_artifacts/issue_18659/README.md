# OpenSSL PoC Artifact: issue_18659

## Source

- Issue: https://github.com/openssl/openssl/issues/18659
- Title: CONF_modules_unload after OPENSSL_cleanup causes segfault
- State: closed

## PoC Information

- PoC type: C_API+STACKTRACE
- Component: CONF/OPENSSL
- Trigger behavior: SEGV
- Affected version: None
- Quality: HQ

## Root Cause

None

## Critical APIs

- OPENSSL_cleanup
- CONF_modules_unload

## Reproduction Command From JSON

['clang++ -fsanitize=address -std=c++11 test.cpp -o test.elf -lcrypto -lssl && ./test.elf']

## Notes

This artifact was generated from structured PoC JSON.

The local validation only proves that the PoC can be compiled and executed against the currently linked OpenSSL library.
Strict reproduction requires compiling and running against the original affected OpenSSL version.
