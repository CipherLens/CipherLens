# OpenSSL CLI-to-C PoC Candidate: issue_27572

## Source

- Issue: https://github.com/openssl/openssl/issues/27572
- Title: openssl cmp -cmd cr corrupts UTF-8 subject names

## Original CLI Command

openssl asn1parse -inform DER -in req.der

## Generated C API Path

- BIO_new_file
- BIO_read
- ASN1_parse_dump

## PoC Info

- Original PoC type: CLI+INPUT_SEED
- Component: CMP/ASN1
- Trigger behavior: WRONG_OUTPUT
- Affected version: 3.3.3
- Quality: HQ

## Root Cause

Hardcoded use of MBSTRING_ASC when calling parse_name

## Notes

This artifact is a candidate C harness translated from the original CLI PoC.

It requires the original input file at:

inputs/req.der

If a placeholder input is used, the result only validates harness compilation/execution, not strict vulnerability reproduction.
