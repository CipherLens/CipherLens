# OpenSSL CLI-to-C PoC Candidate: issue_13860

## Source

- Issue: https://github.com/openssl/openssl/issues/13860
- Title: openssl-x509: change of behaviour for public key output between versions 1.0.2 and 1.1.1

## Original CLI Command

openssl x509 -in cert.crt -inform der -out cert.pem -pubkey

## Generated C API Path

- BIO_new_file
- d2i_X509_bio
- X509_get_pubkey
- PEM_write_PUBKEY

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: X509/X509V3/ASN1
- Trigger behavior: UNKNOWN
- Affected version: 1.0.2, 1.1.1
- Quality: HIGH_CANDIDATE

## Root Cause

Change in behavior of public key output in OpenSSL x509 command between versions 1.0.2 and 1.1.1

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.

It requires the original input file at:

inputs/cert.crt

If a placeholder input is used, the result only validates harness compilation/execution, not strict vulnerability reproduction.
