# OpenSSL CLI-to-C PoC Candidate: issue_30432

## Source

- Issue: https://github.com/openssl/openssl/issues/30432
- Title: dsa_with_SHA384 and dsa_with_SHA512 verify error
- Template: dsa_verify_chain

## Original CLI Command

openssl verify -CAfile ca_cert.pem ee_cert.pem

## Generated C API Path

- PEM_read_bio_X509
- X509_STORE_new
- X509_STORE_add_cert
- X509_STORE_CTX_new
- X509_STORE_CTX_init
- X509_verify_cert

## Expected Inputs

- inputs/ca_cert.pem
- inputs/ee_cert.pem

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: PKEY/DSA/RSA
- Trigger behavior: VERIFY_ERROR
- Affected version: 3.0.15, 3.5.4
- Quality: HIGH_CANDIDATE

## Root Cause

OID of dsa_with_SHA384-512 is incorrect

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
