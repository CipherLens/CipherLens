# OpenSSL CLI-to-C PoC Candidate: issue_23325

## Source

- Issue: https://github.com/openssl/openssl/issues/23325
- Title: X509: wrongly rejects cert without CDP if CRL contains IDP with name matching cert issuer
- Template: verify_with_crl

## Original CLI Command

openssl verify -trusted cacert.pem -crl_check -CRLfile crl.pem cert.pem

## Generated C API Path

- PEM_read_bio_X509
- PEM_read_bio_X509_CRL
- X509_STORE_new
- X509_STORE_add_cert
- X509_STORE_add_crl
- X509_STORE_set_flags
- X509_STORE_CTX_new
- X509_STORE_CTX_init
- X509_verify_cert

## Expected Inputs

- inputs/cacert.pem
- inputs/crl.pem
- inputs/cert.pem

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: X509/CRL
- Trigger behavior: WRONG_RESULT
- Affected version: None
- Quality: HIGH_CANDIDATE

## Root Cause

Incomplete implementation of CRL scope checks in case an IDP is present in a CRL but no CDPs are present in the target cert.

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
