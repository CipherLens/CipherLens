# Version Matrix

## PoC

- PoC ID: WOLFSSL-POC-0005
- CVE: CVE-2026-5264
- Input type: reconstructed DTLS 1.3 ACK record stress pattern
- Input provenance: reconstructed_from_official_pr_10076_test_pattern
- Bug class: DTLS 1.3 ACK record processing heap buffer overflow
- Harness family: dtls13_ack_record_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Build Configuration

The vulnerable reproduction used:

- CFLAGS: -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
- LDFLAGS: -fsanitize=address,undefined
- Configure options:
  - --enable-debug
  - --enable-opensslextra
  - --enable-dtls
  - --enable-dtls13
  - --enable-testcert

## Matrix

| Version / Commit | Role | Result | Evidence |
|---|---|---|---|
| wolfSSL v5.9.0-stable, commit 922d04b3568c6428a9fb905ddee3ef5a68db3108 | vulnerable version | confirmed crash | 4097 ACK records; ASan unknown-crash / out-of-bounds heap write; WRITE of size 8; c64toa; Dtls13WriteAckMessage; 0 bytes after heap region; exit 134 |
| wolfSSL v5.9.1-stable | fixed release candidate | safe execution | 4097 attempted ACK records; seenRecordsCount 128; Dtls13WriteAckMessage returned 0; encoded ACK length 2050; exit 0; no ASan crash |
| current wolfSSL v5.9.1-stable-1373-g8fca95ce6, commit 8fca95ce651d6e370d91f5598786de4bc66aa2c2 | current version | safe execution | 4097 attempted ACK records; seenRecordsCount 128; Dtls13WriteAckMessage returned 0; encoded ACK length 2050; exit 0; no ASan crash |

## Conclusion

WOLFSSL-POC-0005 has confirmed vulnerable-version reproduction on wolfSSL v5.9.0-stable. The reconstructed DTLS 1.3 ACK stress pattern triggers a sanitizer-visible out-of-bounds heap write in Dtls13WriteAckMessage after 4097 ACK records are added.

Release-level and current-version validation are complete: wolfSSL v5.9.1-stable and current wolfSSL safely bound the ACK record list to seenRecordsCount 128 and execute the same stress pattern without sanitizer crash evidence.
