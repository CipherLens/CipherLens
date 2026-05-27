# OpenSSL CLI-to-C PoC Candidate: issue_22388

## Source

- Issue: https://github.com/openssl/openssl/issues/22388
- Title: Support X25519 and X448 in CMS
- Template: cms_encrypt_decrypt

## Original CLI Command

openssl cms -encrypt -stream -binary -keyid -outform DER -recip cert.pem -in hello.txt -out hello.der

## Generated C API Path

- PEM_read_bio_X509
- PEM_read_bio_PrivateKey
- BIO_new_file
- CMS_encrypt
- CMS_decrypt

## Expected Inputs

- inputs/cert.pem
- inputs/key.pem
- inputs/hello.txt

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: CMS/X509
- Trigger behavior: WRONG_RESULT
- Affected version: 3.0.8
- Quality: HIGH_CANDIDATE

## Root Cause

operation not supported for this keytype

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
