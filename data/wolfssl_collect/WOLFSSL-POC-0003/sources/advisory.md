# Advisory Evidence

## Public Advisory Summary

CVE-2026-5448 is described as an X.509 date buffer overflow in wolfSSL_X509_notAfter / wolfSSL_X509_notBefore.

The issue is limited to applications directly using the OpenSSL compatibility layer APIs:

- wolfSSL_X509_notAfter
- wolfSSL_X509_notBefore

The public advisory states that this issue does not affect native TLS or certificate verification operations in wolfSSL.

## Expected Vulnerability Shape

The vulnerable behavior should be triggered by:

1. Loading a crafted X.509 certificate.
2. Parsing the certificate into WOLFSSL_X509.
3. Calling wolfSSL_X509_notAfter or wolfSSL_X509_notBefore.
4. Observing ASan/UBSan crash evidence, likely buffer overflow or out-of-bounds memory access.

## Expected Fixed Boundary

NVD reports affected versions up to but excluding 5.9.1. Therefore:

- candidate vulnerable version: wolfSSL v5.9.0-stable
- candidate fixed version: wolfSSL v5.9.1-stable
- current version: current master checkout
