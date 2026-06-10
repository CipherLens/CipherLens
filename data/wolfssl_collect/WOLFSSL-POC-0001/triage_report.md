# Triage Report

## Basic Information

- PoC ID: WOLFSSL-POC-0001
- Source library: wolfSSL
- Target library: none yet
- Source API: wolfSSL_CTX_use_certificate_chain_file
- Target API: pending
- Harness family: x509_asn1_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Execution Summary

- total_cases: 3
- raw_status_counts:
  - abort_134: 3
- verdict_counts:
  - confirmed_crash_reproduction: 3
- total_pairs: 0
- migration_verdict_counts:
  - not_run: 0

## Crash Evidence

- ASAN: yes
- UBSAN: yes
- SEGV: yes
- exit 139: no
- exit 134: yes
- canary corruption: not observed
- heap-buffer-overflow: indirect memory corruption observed through invalid free path
- heap-buffer-underflow: no
- use-after-free: no
- null dereference: no
- out-of-bounds index: yes, index 19 out of bounds for int[19]

## Semantic Evidence

- return-code mismatch: not applicable
- pointer-consumption mismatch: not applicable
- verification-result mismatch: not applicable
- accepted malformed input: not applicable
- output-state mismatch: not applicable

## Differential Evidence

- source verdict: confirmed_crash_reproduction
- target verdict: not_run
- migration verdict: not_run

## Candidate Type

confirmed_crash_reproduction

## Confidence

high

## Current Conclusion

WOLFSSL-POC-0001 successfully reproduces the historical wolfSSL X.509 / ASN.1 parsing memory-safety issue on wolfSSL v4.2.0-stable with ASan/UBSan and the extra certificate/OpenSSL compatibility build configuration. The crafted certificate triggers an out-of-bounds write in GetName at wolfcrypt/src/asn.c:5121, followed by ASan SEGV during FreeDecodedCert.

## Next Recommended Step

Identify the fixed commit or fixed release, then run the same crafted certificate on the fixed and current wolfSSL versions to complete the version matrix. After that, abstract the vulnerability pattern and prepare migration candidates for OpenSSL and mbedTLS X.509 certificate parsing APIs.

## Version Matrix Update

### Vulnerable Version

- Version: wolfSSL v4.2.0-stable
- Result: confirmed crash reproduction
- Evidence:
  - UBSan index 19 out of bounds in GetName
  - ASan SEGV during FreeDecodedCert
  - exit code 134

### Candidate Fix Commit

- Commit: 88bf5d967
- Result: still vulnerable
- Evidence:
  - UBSan index out of bounds
  - ASan SEGV during FreeDecodedCert
  - exit code 134

### Fixed Release Candidate

- Version: wolfSSL v4.3.0-stable
- Result: safe reject
- Evidence:
  - GetLength value exceeds buffer length
  - no UBSan / ASan / SEGV

### Current Version

- Version: v5.9.1-stable-1299-geeab53205
- Commit: eeab53205ab57451778f7a76aad25f5349547ce5
- Result: safe reject
- Evidence:
  - GetLength - value exceeds buffer length
  - no UBSan / ASan / SEGV

## Final Triage Conclusion

WOLFSSL-POC-0001 is a confirmed historical crash reproduction with complete release-level version evidence. It is suitable as a Q1 strict reproduction candidate, regression test seed, and cross-library X.509 / ASN.1 parser migration seed.
