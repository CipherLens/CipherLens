# OpenSSL CLI-to-C PoC Candidate: issue_29574

## Source

- Issue: https://github.com/openssl/openssl/issues/29574
- Title: Loading "short" certificate is accepted but corrupts openssl
- Template: x509_short_cert_parse

## Original CLI Command

openssl x509 -noout -text -in cert.disk

## Generated C API Path

- BIO_new_file
- PEM_read_bio_X509
- d2i_X509_bio
- X509_print_fp
- X509_free

## Expected Inputs

- inputs/cert.disk

## PoC Info

- Original PoC type: C_API+CLI+INPUT_SEED
- Component: X509/X509V3/ASN1
- Trigger behavior: CORRUPTED_STATE
- Affected version: None
- Quality: HIGH_CANDIDATE

## Root Cause

None

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
