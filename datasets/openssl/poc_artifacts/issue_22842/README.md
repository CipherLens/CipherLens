# OpenSSL RAG-Seed-to-C Candidate: issue_22842

## Source

- Issue: https://github.com/openssl/openssl/issues/22842
- Title: SIGSEGV from EVP_MAC_CTX_get_mac_size()
- Template: evp_mac_size_candidate

## Generated C API Path

- EVP_MAC_fetch
- EVP_MAC_CTX_new
- EVP_MAC_init
- EVP_MAC_CTX_get_mac_size
- EVP_MAC_CTX_free
- EVP_MAC_free

## Expected Inputs

- No external input required

## PoC Info

- Original PoC type: C_API
- Component: EVP/MAC
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 3.1.1
- Quality: HQ

## Root Cause

NULL pointer dereference in EVP_MAC_CTX_get_mac_size() due to uninitialized algctx cipher struct

## Notes

candidate harness generated from semantic seed; not strict reproduction.
The harness is intended to validate that the selected API path compiles and
executes with controlled success or controlled error handling on OpenSSL 3.x.
