# OpenSSL CLI-to-C PoC Candidate: issue_14457

## Source

- Issue: https://github.com/openssl/openssl/issues/14457
- Title: Self-signed certificates generated with a single `openssl req` command fail to verify (error 20 at 0 depth lookup: unable to get local issuer certificate)
- Template: x509_self_verify

## Original CLI Command

openssl verify -CAfile root.cer root.cer

## Generated C API Path

- PEM_read_bio_X509
- X509_STORE_new
- X509_STORE_add_cert
- X509_STORE_CTX_new
- X509_STORE_CTX_init
- X509_verify_cert

## Expected Inputs

- inputs/root.cer

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: X509/X509V3/ASN1
- Trigger behavior: WRONG_OUTPUT
- Affected version: 1.1.1, 1.1.1f
- Quality: HQ

## Root Cause

CONFIGURATION_FILE_EXTENSION_OVERRIDE

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
