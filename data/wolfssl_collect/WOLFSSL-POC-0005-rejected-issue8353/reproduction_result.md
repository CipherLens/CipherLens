# WOLFSSL-POC-0005 Reproduction Result

## Candidate

- Source: GitHub issue #8353
- Theme: PEM / DER / Base64 decoding
- Reported issue: heap-buffer-overflow in pem.c
- Reported version: v5.7.4-stable-372-g4bdccac58
- Candidate API: wc_PemToDer

## Current Status

Candidate selected. Reproduction not started yet.

## Key Verification Question

The first task is to determine whether the crash occurs inside wolfSSL library code or in the issue-provided harness.

If the sanitizer trace points to wolfSSL library code, continue as Q1/Q2 candidate.

If the sanitizer trace points only to harness-side parsing or string handling, reject or downgrade this candidate.

## Minimal API Probe: wc_PemToDer

### Build

- Candidate vulnerable commit: 4bdccac58440cc589807d21d36af2331f3b8817b
- Build description: v5.2.1-73-g4bdccac58
- Build mode: ASan/UBSan, debug, -O0
- Library path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-issue8353-asan

### Input

- Input file: inputs/original/pem-test-from-issue-8353.pem
- Input length observed by harness: 700 bytes
- Input provenance: reconstructed from GitHub issue #8353

### Harness

- Harness source: poc/poc_pem_to_der_min.c
- Triggered API: wc_PemToDer
- Type argument: CERT_TYPE

### Observed Result

The minimal wc_PemToDer API probe did not reproduce an ASan crash.

Observed behavior:

- wc_PemToDer returned: 0
- DerBuffer pointer was non-null
- wc_FreeDer completed
- Exit code: 0
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No ABORTING

### Current Interpretation

The issue #8353 input does not trigger a sanitizer-visible crash through the minimal wc_PemToDer(CERT_TYPE) API path. The next step is to reproduce or inspect the issue-provided example/pem/pem.c style harness to determine whether the reported crash occurs inside wolfSSL library code or in example-side parsing / buffer handling logic.

## Minimal API Probe: wc_PemToDer

### Build

- Candidate vulnerable commit: 4bdccac58440cc589807d21d36af2331f3b8817b
- Build description: v5.2.1-73-g4bdccac58
- Build mode: ASan/UBSan, debug, -O0
- Library path: ~/workplace/CryptoPoc/Builds/wolfssl_repro/wolfssl-issue8353-asan

### Input

- Input file: inputs/original/pem-test-from-issue-8353.pem
- Input length observed by harness: 700 bytes
- Input provenance: reconstructed from GitHub issue #8353

### Harness

- Harness source: poc/poc_pem_to_der_min.c
- Triggered API: wc_PemToDer
- Type argument: CERT_TYPE

### Observed Result

The minimal wc_PemToDer API probe did not reproduce an ASan crash.

Observed behavior:

- wc_PemToDer returned: 0
- DerBuffer pointer was non-null
- wc_FreeDer completed
- Exit code: 0
- No ERROR: AddressSanitizer
- No heap-buffer-overflow
- No ABORTING

### Current Interpretation

The issue #8353 input does not trigger a sanitizer-visible crash through the minimal wc_PemToDer(CERT_TYPE) API path. The next step is to reproduce or inspect the issue-provided example/pem/pem.c style harness to determine whether the reported crash occurs inside wolfSSL library code or in example-side parsing / buffer handling logic.

## Candidate Rejection Decision

### Decision

This candidate is rejected as a strict wolfSSL vulnerability reproduction.

### Reason

The minimal wc_PemToDer(CERT_TYPE) API harness on commit 4bdccac58440cc589807d21d36af2331f3b8817b returned successfully and did not trigger sanitizer evidence.

Additional issue discussion indicates that the reported crash was caused by the issue-provided harness reading a file into a buffer without appending a NULL terminator, then calling strlen on that non-terminated buffer. This causes strlen to read past the allocated file buffer before wolfSSL is called.

### Final Classification

- strict_reproduction: false
- vulnerable_version_verified: false
- quality_level: Q5_rejected_harness_bug
- verdict: rejected_not_wolfssl_bug

### Evidence

- Minimal API harness: poc/poc_pem_to_der_min.c
- Input: inputs/original/pem-test-from-issue-8353.pem
- Log: logs/vulnerable_version/wolfssl-issue8353-asan/pem_to_der_min_repro.log
- Exit code: logs/vulnerable_version/wolfssl-issue8353-asan/pem_to_der_min_exit_code.txt
- Grep result: logs/vulnerable_version/wolfssl-issue8353-asan/asan_grep_result.txt

### Note

This artifact is retained as a negative screening example showing why issue-level reports must be distinguished from library-internal vulnerabilities.
