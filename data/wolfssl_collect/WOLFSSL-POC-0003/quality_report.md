# PoC Quality Report

## Basic Information

- PoC ID: WOLFSSL-POC-0003
- Source library: wolfSSL
- CVE: CVE-2026-5448
- Title: wolfSSL X.509 date buffer overflow in wolfSSL_X509_notAfter / wolfSSL_X509_notBefore
- Bug class: X.509 date parsing buffer overflow
- Harness family: x509_date_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Input Quality

- Has original bug-triggering certificate input: false
- Uses placeholder input: false
- Input provenance: reconstructed_from_pr_10071_official_test_pattern
- Input type: crafted WOLFSSL_ASN1_TIME object
- Crafted input details:
  - type: ASN_UTC_TIME
  - length: 255
  - data: initialized safely inside WOLFSSL_ASN1_TIME::data

## Reproduction Status

- Vulnerable version verified: true
- Fixed release verified: true
- Current version verified: true
- Original failure signal preserved: true
- Strict reproduction: true
- Exact fixed commit identified: false

## Successful Vulnerable Reproduction

- Version: wolfSSL v5.9.0-stable
- Commit: 922d04b3568c6428a9fb905ddee3ef5a68db3108
- Result: confirmed crash
- Evidence:
  - notAfter path: ASan heap-buffer-overflow, WRITE of size 255, exit code 134
  - notBefore path: ASan heap-buffer-overflow, WRITE of size 255, exit code 134

## Fixed Release Verification

- Version: wolfSSL v5.9.1-stable
- Commit: 1d363f3adceba9d1478230ede476a37b0dcdef24
- Result: safe rejection
- Evidence:
  - notAfter exit code: 1
  - notBefore exit code: 1
  - NO_CRASH_SIGNAL
  - no ASan heap-buffer-overflow

The exit code 1 is expected because the fixed version rejects the oversized ASN1_TIME length instead of processing it.

## Current Version Verification

- Version description: v5.9.1-stable-1373-g8fca95ce6
- Commit: 8fca95ce651d6e370d91f5598786de4bc66aa2c2
- Result: safe rejection
- Evidence:
  - notAfter exit code: 1
  - notBefore exit code: 1
  - NO_CRASH_SIGNAL
  - no ASan heap-buffer-overflow

## Version Matrix Status

- Vulnerable version verified: true
- Fixed release verified: true
- Current version verified: true
- Release-level fixed boundary:
  - vulnerable: v5.9.0-stable
  - fixed release candidate: v5.9.1-stable

## Quality Level

Current quality level:

Q1_strict_reproduction_candidate

## Final Quality Judgment

This PoC is a high-quality API-level historical vulnerability reproduction sample. It has PR-based trigger reconstruction, vulnerable-version ASan heap-buffer-overflow evidence, fixed-release safe-rejection evidence, and current-version safe-rejection evidence.

## Recommended Usage

- discovery_seed: yes
- regression_test: yes
- x509_date_parser_memory_safety_seed: yes
- cross_library_migration_candidate: yes
- semantic_seed: no
- negative_control: no
- documentation_only: no

## Remaining Limitation

This PoC currently uses an API-level crafted WOLFSSL_ASN1_TIME object reconstructed from PR 10071's official test pattern. It does not yet include a certificate-level malformed X.509 file that triggers the same behavior through certificate parsing.
