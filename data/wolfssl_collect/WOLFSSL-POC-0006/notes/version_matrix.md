# WOLFSSL-POC-0006 Version Matrix

## Vulnerable Version

- Version: wolfSSL v5.8.4-stable
- Commit: 59f4fa568615396fbf381b073b220d1e8d61e4c2
- Result: ASan stack-buffer-overflow
- Crash path:
  - EncodeAttributes
  - wc_PKCS7_BuildSignedAttributes
  - wc_PKCS7_EncodeSignedData
- Signal:
  - WRITE of size 8
  - stack-buffer-overflow
  - exit code 134

## Fixed Version

- Version: wolfSSL v5.9.0-stable
- Result: no ASan crash
- Observed return:
  - wc_PKCS7_EncodeSignedData returned -132
- Fix behavior:
  - oversized custom signed attribute list is rejected before EncodeAttributes writes past signedAttribs[7]

## Current Version

- Version: wolfSSL current master
- Result: no ASan crash
- Observed return:
  - wc_PKCS7_EncodeSignedData returned -132
- Summary:
  - NO_ASAN_CRASH_OBSERVED
