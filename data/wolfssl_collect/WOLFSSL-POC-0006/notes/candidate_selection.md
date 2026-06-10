# WOLFSSL-POC-0006 Candidate Selection

## Selected Candidate

- Candidate PoC ID: WOLFSSL-POC-0006
- CVE: CVE-2026-0819
- Module family: PKCS#7
- Bug class: PKCS7 SignedData encoding out-of-bounds write
- Primary API surface:
  - wc_PKCS7_EncodeSignedData
  - wc_PKCS7_EncodeSignedData_ex
- Expected vulnerable source region:
  - wolfcrypt/src/pkcs7.c
  - wc_PKCS7_BuildSignedAttributes
  - EncodeAttributes
  - signedAttribs / signedAttribsCount

## Selection Rationale

This candidate is selected because it expands the dataset beyond the existing X.509 and DTLS samples.

The issue is a PKCS#7 SignedData encoding bug involving custom signed attributes. The expected root cause is a fixed-size signed attribute array capacity mismatch when more than 7 custom signed attributes are encoded.

## Expected Trigger Shape

- Initialize a PKCS7 SignedData object.
- Configure signing inputs sufficiently for wc_PKCS7_EncodeSignedData or wc_PKCS7_EncodeSignedData_ex.
- Add more than 7 custom signed attributes.
- Trigger SignedData encoding.
- Observe sanitizer-visible out-of-bounds write on vulnerable version.

## Initial Quality Status

- Status: candidate selected
- Vulnerable version: pending
- Fixed version: pending
- Current version: pending
