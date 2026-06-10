# WOLFSSL-POC-0007 Version Matrix

## Vulnerable Version

- Version: wolfSSL v5.9.0-stable
- Result: ASan stack-buffer-overflow
- Trigger:
  - reconstructed PKCS7/CMS EnvelopedData
  - OtherRecipientInfo / ORI recipient
  - ORI OID length: 80 bytes
  - destination: oriOID[MAX_OID_SZ]
- Crash path:
  - wc_PKCS7_DecryptOri
  - wc_PKCS7_DecodeEnvelopedData
- Signal:
  - ERROR: AddressSanitizer: stack-buffer-overflow
  - WRITE of size 80
  - oriOID overflow
  - ABORTING

## Fixed Version

- Version: wolfSSL v5.9.1-stable
- Result: no ASan crash
- Observed return:
  - wc_PKCS7_DecodeEnvelopedData returned -140
- Fix behavior:
  - oversized ORI OID is rejected before copying into oriOID[MAX_OID_SZ]

## Current Version

- Version: wolfSSL current master
- Result: no ASan crash
- Observed return:
  - wc_PKCS7_DecodeEnvelopedData returned -140
- Summary:
  - NO_ASAN_CRASH_OBSERVED
