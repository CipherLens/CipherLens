# OpenSSL CLI-to-C PoC Candidate: issue_30889

## Source

- Issue: https://github.com/openssl/openssl/issues/30889
- Title: Segfault in 'openssl pkey' for interactive encryption (v4.0.0)
- Template: pkey_encrypt_output

## Original CLI Command

openssl pkey -in plain.pem -aes-256-cbc -out enc.pem

## Generated C API Path

- PEM_read_bio_PrivateKey
- PEM_write_bio_PrivateKey
- EVP_PKEY_free

## Expected Inputs

- inputs/plain.pem

## PoC Info

- Original PoC type: CLI
- Component: PKEY/ML-DSA/RSA
- Trigger behavior: SEGV
- Affected version: 4.0.0
- Quality: HQ

## Root Cause

NULL_DEREFERENCE_CRASH

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
