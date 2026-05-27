# OpenSSL CLI-to-C PoC Candidate: issue_30291

## Source

- Issue: https://github.com/openssl/openssl/issues/30291
- Title: CMS regression: signed attributes with ED448
- Template: cms_sign_verify

## Original CLI Command

openssl cms -sign -signer cert.pem -inkey key.pem -in text.txt -out out.cms -md shake256; openssl cms -verify -in out.cms -CAfile cert.pem -content text.txt

## Generated C API Path

- PEM_read_bio_X509
- PEM_read_bio_PrivateKey
- BIO_new_file
- CMS_sign
- CMS_verify
- CMS_ContentInfo_free

## Expected Inputs

- inputs/cert.pem
- inputs/key.pem
- inputs/text.txt

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: CMS/ED448
- Trigger behavior: REGRESSION_TEST
- Affected version: 3.5, 3.6
- Quality: HIGH_CANDIDATE

## Root Cause

REGRESSION

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.
It is not marked as a strict vulnerability reproduction because the original
input artifacts are not bundled here.
