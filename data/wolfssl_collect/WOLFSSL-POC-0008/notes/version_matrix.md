# WOLFSSL-POC-0008 Version Matrix

## Vulnerable Version

- Version: wolfSSL v5.9.0-stable
- Build flags:
  - --enable-debug
  - --enable-tls13
  - --enable-ecc
  - --enable-supportedcurves
  - --enable-experimental
  - --enable-mlkem
  - CFLAGS includes -DWOLFSSL_PQC_HYBRIDS
- Trigger:
  - malicious TLS 1.3 ServerHello
  - PQC hybrid KeyShare group: WOLFSSL_SECP256R1MLKEM768
  - truncated key_exchange length: 10 bytes
- Runtime path:
  - wolfSSL_UseKeyShare
  - wolfSSL_connect_TLSv13
  - wolfSSL_free
- Result:
  - ASan heap-use-after-free
- Signal:
  - WRITE of size 8
  - ForceZero
  - TLSX_KeyShare_FreeAll
  - TLSX_FreeAll
  - wolfSSL_free
  - earlier free path includes TLSX_KeyShare_ProcessPqcHybridClient
  - ABORTING

## Fixed Version

- Version: wolfSSL v5.9.1-stable
- Build flags:
  - same PQC hybrid / ML-KEM / TLS 1.3 ASan configuration
- Result:
  - no ASan crash
- Observed behavior:
  - wolfSSL_UseKeyShare returned 1
  - wolfSSL_connect_TLSv13 returned -1
  - wolfSSL_free done
  - cleanup done
  - NO_ASAN_CRASH_OBSERVED

## Current Version

- Version: wolfSSL current master
- Build flags:
  - same PQC hybrid / ML-KEM / TLS 1.3 ASan configuration
- Result:
  - no ASan crash
- Observed behavior:
  - wolfSSL_UseKeyShare returned 1
  - wolfSSL_connect_TLSv13 returned -1
  - wolfSSL_free done
  - cleanup done
  - NO_ASAN_CRASH_OBSERVED
