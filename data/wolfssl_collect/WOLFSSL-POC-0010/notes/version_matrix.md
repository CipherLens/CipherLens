# WOLFSSL-POC-0010 Version Matrix

## Vulnerable Version

- Version: wolfSSL v5.8.4-stable
- Build flags:
  - --enable-debug
  - --enable-alpn
  - --enable-opensslall
- Trigger:
  - direct call to wolfSSL_select_next_proto
  - malformed length-prefixed protocol lists
  - serverList length byte: 200
  - serverList actual heap buffer size: 5
  - clientList length byte: 200
  - clientList actual heap buffer size: 5
- Runtime path:
  - wolfSSL_select_next_proto
  - memcmp / XMEMCMP
- Result:
  - ASan heap-buffer-overflow
- Signal:
  - READ of size 200
  - wolfSSL_select_next_proto
  - src/ssl.c:22298
  - ABORTING

## Fixed Version

- Version: wolfSSL v5.9.0-stable
- Build flags:
  - same ALPN / OpenSSL API ASan configuration
- Result:
  - no ASan crash
- Observed behavior:
  - wolfSSL_select_next_proto returned: 2
  - outLen: 0
  - cleanup done
  - NO_ASAN_CRASH_OBSERVED

## Current Version

- Version: wolfSSL current master
- Build flags:
  - same ALPN / OpenSSL API ASan configuration
- Result:
  - no ASan crash
- Observed behavior:
  - wolfSSL_select_next_proto returned: 2
  - outLen: 0
  - cleanup done
  - NO_ASAN_CRASH_OBSERVED
