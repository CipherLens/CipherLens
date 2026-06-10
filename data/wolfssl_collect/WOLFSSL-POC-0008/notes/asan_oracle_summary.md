# WOLFSSL-POC-0008 ASan Oracle Summary

## Vulnerable Signal

The vulnerable wolfSSL v5.9.0-stable build produces:

- ERROR: AddressSanitizer: heap-use-after-free
- WRITE of size 8
- ForceZero wolfcrypt/src/misc.c
- TLSX_KeyShare_FreeAll src/tls.c
- TLSX_FreeAll src/tls.c
- wolfSSL_free src/ssl.c

The earlier free path includes:

- TLSX_KeyShare_ProcessPqcHybridClient src/tls.c
- wolfSSL_connect_TLSv13 src/tls13.c
- wolfSSL_UseKeyShare src/tls13.c

## Fixed / Current Signal

The fixed and current builds complete cleanup without sanitizer errors:

- wolfSSL_UseKeyShare returned: 1
- wolfSSL_connect_TLSv13 returned: -1
- wolfSSL_free done
- cleanup done
- NO_ASAN_CRASH_OBSERVED
