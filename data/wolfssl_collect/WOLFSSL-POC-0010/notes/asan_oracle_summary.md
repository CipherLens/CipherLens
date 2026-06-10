# WOLFSSL-POC-0010 ASan Oracle Summary

## Vulnerable Signal

The vulnerable wolfSSL v5.8.4-stable build produces:

- ERROR: AddressSanitizer: heap-buffer-overflow
- READ of size 200
- memcmp / XMEMCMP path
- wolfSSL_select_next_proto
- src/ssl.c:22298
- SUMMARY: AddressSanitizer: heap-buffer-overflow
- ABORTING

The overflow address is located immediately after a 5-byte heap region allocated for the malformed protocol list.

## Fixed / Current Signal

The fixed and current builds safely handle the malformed protocol lists:

- wolfSSL_select_next_proto returned: 2
- outLen: 0
- cleanup done
- NO_ASAN_CRASH_OBSERVED
