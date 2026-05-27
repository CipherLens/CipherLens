# OpenSSL PoC Artifact: issue_2630

## Source

- Issue: https://github.com/openssl/openssl/issues/2630
- Title: Secure heap impl.: segmentation fault in sh_add_to_list for small allocations
- State: closed

## PoC Information

- PoC type: C_API
- Component: BIO/SECURE_HEAP
- Trigger behavior: SEGV
- Affected version: None
- Quality: HQ

## Root Cause

None

## Critical APIs

- CRYPTO_secure_malloc_init
- BIO_new
- BIO_write

## Reproduction Command From JSON

['example1();', 'example2();']

## Notes

This artifact was generated from structured PoC JSON.

The local validation only proves that the PoC can be compiled and executed against the currently linked OpenSSL library.
Strict reproduction requires compiling and running against the original affected OpenSSL version.
