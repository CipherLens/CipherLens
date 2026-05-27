# OpenSSL RAG-Seed-to-C Candidate: issue_19524

## Source

- Issue: https://github.com/openssl/openssl/issues/19524
- Title: ED25519_sign and ED448_sign missing check for private_key leading to segfault
- Template: ed25519_digestsign_candidate

## Generated C API Path

- EVP_PKEY_new_raw_public_key
- EVP_MD_CTX_new
- EVP_DigestSignInit
- EVP_DigestSign
- EVP_MD_CTX_free
- EVP_PKEY_free

## Expected Inputs

- No external input required

## PoC Info

- Original PoC type: C_API
- Component: PKEY/ED25519/ED448
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: openssl3.0.2, openssl 1.1.1r
- Quality: HQ

## Root Cause

EVP_DigestUpdate() allows NULL to get passed to it, and digests don't check for NULL.

## Notes

candidate harness generated from semantic seed; not strict reproduction.
The harness is intended to validate that the selected API path compiles and
executes with controlled success or controlled error handling on OpenSSL 3.x.
