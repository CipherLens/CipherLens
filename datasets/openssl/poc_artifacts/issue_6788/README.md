# OpenSSL CLI-to-C PoC Candidate: issue_6788

## Source

- Issue: https://github.com/openssl/openssl/issues/6788
- Title: openssl crl does not work properly if -CAfile contains multiple CA certs with the same subject
- Template: crl_parse

## Original CLI Command

openssl crl -in crl.pem -noout -issuer

## Generated C API Path

- BIO_new_file
- PEM_read_bio_X509_CRL
- X509_CRL_get_issuer
- X509_NAME_print_ex_fp
- X509_CRL_free

## Expected Inputs

- inputs/crl.pem

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: CRL/X509
- Trigger behavior: WRONG_RESULT
- Affected version: None
- Quality: HIGH_CANDIDATE

## Root Cause

The crl application's use of X509_STORE_CTX_get_obj_by_subject, which matches the first certificate with an identical subject, relies on the unstable qsort function to sort certificates before the lookup, resulting in inconsistent verification behavior.

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
