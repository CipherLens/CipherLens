# OpenSSL CLI-to-C PoC Candidate: issue_30581

## Source

- Issue: https://github.com/openssl/openssl/issues/30581
- Title: NULL pointer dereference in openssl pkcs12 -info when printing PBMAC1 salt metadata
- Template: pkcs12_info_parse

## Original CLI Command

openssl pkcs12 -in test.p12 -info -noout -passin pass:testpassword

## Generated C API Path

- fopen
- d2i_PKCS12_fp
- PKCS12_mac_present
- PKCS12_verify_mac
- PKCS12_parse
- PKCS12_free

## Expected Inputs

- inputs/test.p12

## PoC Info

- Original PoC type: CLI+INPUT_SEED+CLI+SANITIZER_LOG
- Component: PKCS12/ASN1
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: OpenSSL 4.1.0-dev
- Quality: HIGH_CANDIDATE

## Root Cause

Dereferencing a NULL pointer when decoding PBKDF2 salt as ASN.1 NULL in the CLI info path.

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
