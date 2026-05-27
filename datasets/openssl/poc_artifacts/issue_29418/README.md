# OpenSSL CLI-to-C PoC Candidate: issue_29418

## Source

- Issue: https://github.com/openssl/openssl/issues/29418
- Title: openssl x509 -purpose produces inconsistent results depending on parsing options

## Original CLI Command

openssl x509 -in servercert.pem -noout -purpose

## Generated C API Path

- BIO_new_file
- PEM_read_bio_X509
- X509_check_purpose

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: X509/X509V3/ASN1
- Trigger behavior: WRONG_RESULT
- Affected version: 3.0.13
- Quality: HQ

## Root Cause

Inconsistent handling of extensions when using the -ext option with openssl x509 command.

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.

It requires the original input file at:

inputs/servercert.pem

If a placeholder input is used, the result only validates harness compilation/execution, not strict vulnerability reproduction.
