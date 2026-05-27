# OpenSSL RAG-Seed-to-C Candidate: issue_9043

## Source

- Issue: https://github.com/openssl/openssl/issues/9043
- Title: NULL pointer dereference in CSR text output code
- Template: csr_text_output_candidate

## Generated C API Path

- BIO_new_file
- PEM_read_bio_X509_REQ
- X509_REQ_print_fp
- X509_REQ_free

## Expected Inputs

- inputs/req.pem

## PoC Info

- Original PoC type: INPUT_SEED
- Component: X509/CSR/ASN1
- Trigger behavior: NULL_DEREFERENCE_CRASH
- Affected version: 1.1.1b
- Quality: HQ

## Root Cause

NULL pointer dereference in CSR text output code

## Notes

candidate harness generated from semantic seed; not strict reproduction.
The harness is intended to validate that the selected API path compiles and
executes with controlled success or controlled error handling on OpenSSL 3.x.
