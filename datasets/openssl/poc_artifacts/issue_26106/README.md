# OpenSSL CLI-to-C PoC Candidate: issue_26106

## Source

- Issue: https://github.com/openssl/openssl/issues/26106
- Title: Segmentation fault in X509_ALGOR_get0 during PKCS#12 processing 
- Template: pkcs12_parse

## Original CLI Command

openssl pkcs12 -in X509_ALGOR_get0_testpassword.pk12 -passin pass:testpassword

## Generated C API Path

- fopen
- d2i_PKCS12_fp
- PKCS12_parse
- PKCS12_free

## Expected Inputs

- inputs/test.p12

## PoC Info

- Original PoC type: INPUT_SEED+CLI+SANITIZER_LOG
- Component: PKCS12/X509_ALGOR
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 3.4, 3.5.0-dev
- Quality: HQ

## Root Cause

NULL pointer dereference in X509_ALGOR_get0 during PKCS#12 processing

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
