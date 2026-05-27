# OpenSSL RAG-Seed-to-C Candidate: issue_29645

## Source

- Issue: https://github.com/openssl/openssl/issues/29645
- Title: BIO_set_data() causes crash
- Template: bio_set_data_candidate

## Generated C API Path

- BIO_new
- BIO_s_mem
- BIO_set_data
- BIO_get_data
- BIO_free

## Expected Inputs

- No external input required

## PoC Info

- Original PoC type: C_API+SANITIZER_LOG
- Component: BIO/CONF/ERR
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 3.5.4
- Quality: HQ

## Root Cause

NULL pointer dereference in BIO_free when called with a BIO that was not properly initialized

## Notes

candidate harness generated from semantic seed; not strict reproduction.
The harness is intended to validate that the selected API path compiles and
executes with controlled success or controlled error handling on OpenSSL 3.x.
