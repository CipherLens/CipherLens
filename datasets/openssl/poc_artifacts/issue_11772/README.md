# OpenSSL CLI-to-C PoC Candidate: issue_11772

## Source

- Issue: https://github.com/openssl/openssl/issues/11772
- Title: openssl x509 returns 0 even though the date of certificate is invalid

## Original CLI Command

openssl x509 -in $PoC -checkend 0 -noout

## Generated C API Path

- BIO_new_file
- PEM_read_bio_X509
- X509_get0_notAfter
- X509_cmp_time

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: X509/X509V3/ASN1
- Trigger behavior: WRONG_RESULT
- Affected version: openssl-1.0.2u
- Quality: HIGH_CANDIDATE

## Root Cause

The function calling X509_cmp_time() doesn't check that it returned an error.

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.

It requires the original input file at:

inputs/poc.pem

If a placeholder input is used, the result only validates harness compilation/execution, not strict vulnerability reproduction.
