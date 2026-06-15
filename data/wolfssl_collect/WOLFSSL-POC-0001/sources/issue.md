# Issue Evidence

- URL: https://github.com/wolfSSL/wolfssl/issues/2555
- Title: Heap based buffer overflow while parsing crafted X.509 certificates
- Reporter: cve-reporting
- Date: 2019-11-04
- Status: Closed
- Labels: Resolved, bug

## Summary

wolfSSL versions 4.1.0 and 4.2.0 incorrectly handle crafted X.509 certificates, leading to a heap-buffer overflow inside the DecodedCert structure.

The reported root cause is incorrect handling of the loc buffer in the DecodedName structure. The issue states that count can reach 21, while the loc table has fixed size 19.

Relevant vulnerable code location mentioned in the issue:

- wolfcrypt/src/asn.c:5121
- expression: dName->loc[count++] = id

The overflow of issuerName.loc can overwrite subjectName.fullName. During deallocation in FreeDecodedCert, wolfSSL may call free() on the overwritten pointer and crash.

## Affected Versions

- wolfSSL 4.1.0
- wolfSSL 4.2.0

## Triggering Input

The issue provides an attached crafted certificate:

- crash_000_FreeDecodedCert.zip
- expected extracted file: crash_000_FreeDecodedCert.pem

## Reproduction Commands Mentioned

DTLS server startup:

./examples/server/server -u -c crash_000_FreeDecodedCert.pem

TLS server startup:

./examples/server/server -c crash_000_FreeDecodedCert.pem

TLS client startup:

./examples/client/client -c crash_000_FreeDecodedCert.pem

## Failure Signal

- ASAN:SIGSEGV
- crash during FreeDecodedCert
- crash during free() on overwritten subjectName.fullName pointer

## Notes

This PoC is a strong Q1 candidate if the original attached crafted certificate can be collected and the crash can be reproduced on wolfSSL 4.1.0 or 4.2.0.