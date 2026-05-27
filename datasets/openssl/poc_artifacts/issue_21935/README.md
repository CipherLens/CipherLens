# OpenSSL RAG-Seed-to-C Candidate: issue_21935

## Source

- Issue: https://github.com/openssl/openssl/issues/21935
- Title: RSA 1.1.1 API broken in openssl-SNAP-20230831
- Template: rsa_pkey_sign_candidate

## Generated C API Path

- EVP_PKEY_new
- RSA_new
- BN_new
- RSA_set0_key
- EVP_PKEY_assign_RSA
- EVP_MD_CTX_new
- EVP_DigestSignInit
- EVP_MD_CTX_free
- EVP_PKEY_free

## Expected Inputs

- No external input required

## PoC Info

- Original PoC type: C_API+STACKTRACE
- Component: PKEY/RSA
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: openssl-SNAP-20230831
- Quality: HQ

## Root Cause

NULL pointer dereference in BN_is_negative function when handling invalid BIGNUM pointers.

## Notes

candidate harness generated from semantic seed; not strict reproduction.
The harness is intended to validate that the selected API path compiles and
executes with controlled success or controlled error handling on OpenSSL 3.x.
