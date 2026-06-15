# WOLFSSL-POC-0005 Reproduction Result

## Candidate

- CVE: CVE-2026-5264
- Theme: DTLS 1.3 ACK message processing
- Bug class: heap buffer overflow
- Fixed PR: https://github.com/wolfSSL/wolfssl/pull/10076
- Candidate fixed release: wolfSSL 5.9.1 or later
- Input provenance target: reconstructed_from_official_pr_10076_test_pattern

## Rationale

This candidate is selected from the official wolfSSL 2026 vulnerability list.

The vulnerability is described as a heap buffer overflow in DTLS 1.3 ACK message processing. The PR discussion for #10076 indicates that the fix adds ACK record-count bounds and DTLS 1.3 ACK overflow tests. It also mentions an original PoC shape involving 4097 ACK records leading to a large heap overflow.

## Current Status

Candidate selected. Reproduction not started yet.

## Target Verification

The goal is to determine whether a minimal or test-derived DTLS 1.3 ACK harness can reproduce the vulnerable-version crash and then verify safe behavior on the fixed and current versions.

## Vulnerable Version Test: wolfSSL v5.9.0-stable

### Build

- Library: wolfSSL
- Version: v5.9.0-stable
- Commit: 922d04b3568c6428a9fb905ddee3ef5a68db3108
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.0-stable-asan-dtls13-ack
- Build mode: ASan/UBSan, debug, -O0
- Configure focus: DTLS / DTLS 1.3 enabled

### Harness

- Harness source: poc/poc_dtls13_ack_overflow_min.c
- Trigger path:
  - test_memio_setup
  - test_memio_do_handshake
  - Dtls13RtxAddAck
  - Dtls13WriteAckMessage
- ACK record count: 4097

### Observed Result

The vulnerable version reproduces a sanitizer-visible out-of-bounds heap write during DTLS 1.3 ACK message serialization.

Observed behavior:

- DTLS 1.3 manual memio setup succeeded when run from the wolfSSL build root
- DTLS 1.3 handshake succeeded
- 4097 ACK records were added
- Dtls13WriteAckMessage was called
- ASan reported an out-of-bounds write
- WRITE of size 8
- Crash stack includes:
  - c64toa
  - Dtls13WriteAckMessage src/dtls13.c
  - poc_dtls13_ack_overflow_min.c
- Exit code: 134

### Evidence Logs

- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-dtls13-ack/build_info.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-dtls13-ack/dtls13_ack_overflow_min_repro_from_builddir.log
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-dtls13-ack/dtls13_ack_overflow_min_from_builddir_exit_code.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-dtls13-ack/asan_grep_result_from_builddir.txt
- logs/vulnerable_version/wolfssl-v5.9.0-stable-asan-dtls13-ack/asan_precise_crash_signal.txt

### Current Conclusion

wolfSSL v5.9.0-stable is confirmed vulnerable for WOLFSSL-POC-0005. The reconstructed DTLS 1.3 ACK test pattern triggers an out-of-bounds heap write in Dtls13WriteAckMessage.

## Fixed Release Candidate Test: wolfSSL v5.9.1-stable

### Build

- Library: wolfSSL
- Version: v5.9.1-stable
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-v5.9.1-stable-asan-dtls13-ack
- Build mode: ASan/UBSan, debug, -O0
- Configure focus: DTLS / DTLS 1.3 enabled

### Harness

- Harness source: poc/poc_dtls13_ack_overflow_fixed_api.c
- Trigger path:
  - test_memio_setup
  - test_memio_do_handshake
  - Dtls13RtxAddAck
  - Dtls13WriteAckMessage
- Attempted ACK record insertions: 4097

### Observed Result

wolfSSL v5.9.1-stable does not reproduce the sanitizer-visible out-of-bounds write observed on v5.9.0-stable.

Observed behavior:

- DTLS 1.3 manual memio setup succeeded
- DTLS 1.3 handshake succeeded
- 4097 ACK insertions were attempted
- seenRecordsCount was bounded to 128
- Dtls13WriteAckMessage returned: 0
- Encoded ACK length: 2050
- Exit code: 0
- No ERROR: AddressSanitizer
- No WRITE of size
- No ABORTING

### Evidence Logs

- logs/fixed_version/wolfssl-v5.9.1-stable-asan-dtls13-ack/build_info.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-dtls13-ack/dtls13_ack_overflow_fixed_repro.log
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-dtls13-ack/dtls13_ack_overflow_fixed_exit_code.txt
- logs/fixed_version/wolfssl-v5.9.1-stable-asan-dtls13-ack/asan_grep_result.txt

### Current Conclusion

wolfSSL v5.9.1-stable is a fixed release candidate for WOLFSSL-POC-0005. The same DTLS 1.3 ACK stress pattern that triggers an out-of-bounds heap write on v5.9.0-stable executes safely on v5.9.1-stable.

## Current Version Test: current wolfSSL

### Build

- Library: wolfSSL
- Version: current wolfSSL v5.9.1-stable-1373-g8fca95ce6
- Commit: 8fca95ce651d6e370d91f5598786de4bc66aa2c2
- Build path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-current-asan-dtls13-ack
- Build mode: ASan/UBSan, debug, -O0
- Configure focus: DTLS / DTLS 1.3 enabled

### Harness

- Harness source: poc/poc_dtls13_ack_overflow_fixed_api.c
- Trigger path:
  - test_memio_setup
  - test_memio_do_handshake
  - Dtls13RtxAddAck
  - Dtls13WriteAckMessage
- Attempted ACK record insertions: 4097

### Observed Result

Current wolfSSL does not reproduce the sanitizer-visible out-of-bounds heap write observed on v5.9.0-stable.

Observed behavior:

- DTLS 1.3 manual memio setup succeeded
- DTLS 1.3 handshake succeeded
- 4097 ACK insertions were attempted
- seenRecordsCount was bounded to 128
- Dtls13WriteAckMessage returned: 0
- Encoded ACK length: 2050
- Exit code: 0
- No ERROR: AddressSanitizer
- No WRITE of size
- No ABORTING

### Evidence Logs

- logs/current_version/wolfssl-current-asan-dtls13-ack/build_info.txt
- logs/current_version/wolfssl-current-asan-dtls13-ack/dtls13_ack_overflow_current_repro.log
- logs/current_version/wolfssl-current-asan-dtls13-ack/dtls13_ack_overflow_current_exit_code.txt
- logs/current_version/wolfssl-current-asan-dtls13-ack/asan_grep_result.txt

### Current Conclusion

Current wolfSSL safely handles the reconstructed 4097-record DTLS 1.3 ACK stress pattern. The ACK record count is bounded to 128 and no sanitizer crash is observed.
