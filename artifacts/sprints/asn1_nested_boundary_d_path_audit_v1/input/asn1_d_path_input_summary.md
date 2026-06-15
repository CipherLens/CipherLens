# ASN.1 Nested Boundary D-Path Input Summary

## Why This Family

Scheduler selected `asn1_nested_boundary` after AEAD-GCM closure because the GCM candidates were downgraded, while ASN.1/X.509 has existing seeds and a clearer malformed-structure oracle.

## Difference From DER Full-Consumption

- `der_full_consumption`: focuses on valid top-level DER prefix plus trailing garbage after the object.
- `asn1_nested_boundary`: focuses on malformed nested child objects, inner length/end-pointer boundaries, invalid optional fields, and safe rejection inside the parsed object.

## Why D-Path First

`MBEDTLS-POC-0017` is already a useful safe/safe negative case. `OPENSSL-ISSUE-30581` has crash/sanitizer metadata, but local artifact notes say the original input is missing and placeholder input was used, so strict reproduction is not established. That makes D-path evidence audit the right first step.

## Available Seeds

- `MBEDTLS-POC-0017`
- `OPENSSL-ISSUE-30581`
- `OPENSSL-ISSUE-9043`
- `OPENSSL-ISSUE-16196`
- `OPENSSL-ISSUE-18168`
- `OPENSSL-ISSUE-26106`
- `OPENSSL-ISSUE-27572`

## A-Path Possibility

Possible later, but only after seed evidence, minimal reproducer, and oracle are stable.
