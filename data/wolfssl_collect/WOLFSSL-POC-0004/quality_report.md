# PoC Quality Report

## Basic Information

- PoC ID: WOLFSSL-POC-0004
- Source library: wolfSSL
- CVE: CVE-2026-5447
- Title: wolfSSL CertFromX509 AuthorityKeyIdentifier size confusion heap-buffer-overflow
- Bug class: X.509 AuthorityKeyIdentifier heap buffer overflow
- Harness family: x509_authority_key_identifier_memory_safety
- Oracle type: crash_sanitizer_oracle

## Input Quality

- Has original bug-triggering input: false
- Uses placeholder input: false
- Input provenance: reconstructed_from_pr_10112_official_test_pattern
- Input type: reconstructed DER X.509 certificate
- Input file:
  - inputs/reconstructed/cve-2026-5447-akid-overflow-long.der
- SHA256:
  - 429c84c39342e7d668d6ac43dd8d513b6abbcfa8abeee420ce6de689d09b84be

## Reconstructed Trigger

The reconstructed certificate contains an oversized AuthorityKeyIdentifier extension.

Key properties:

- keyIdentifier length: 20 bytes
- full AuthorityKeyIdentifier source length: approximately 20046 bytes
- trigger path:
  - wolfSSL_X509_d2i
  - wolfSSL_i2d_X509_bio
  - wolfssl_x509_make_der
  - CertFromX509

## Root Cause Summary

The vulnerable implementation checks x509->authKeyIdSz against sizeof(cert->akid), but under WOLFSSL_AKID_NAME copies x509->authKeyIdSrcSz bytes into cert->akid.

This creates a size confusion:

- authKeyIdSz is small and passes the old guard.
- authKeyIdSrcSz is large and is copied into the smaller cert->akid buffer.

Local layout probing showed:

- sizeof(Cert): 7432
- offsetof(Cert, akid): 2724
- sizeof(Cert.akid): 1332
- bytes from akid start to Cert end: 4708
- minimum copy length to exceed Cert object: 4709

The long reconstructed AKID source exceeds the Cert heap object boundary and triggers an ASan-visible heap-buffer-overflow.

## Reproduction Status

- Vulnerable version verified: true
- Fixed release verified: true
- Current version verified: true
- Strict reproduction: true
- Exact fixed commit identified: false

## Successful Vulnerable Reproduction

- Version: wolfSSL v5.9.0-stable
- Commit: 922d04b3568c6428a9fb905ddee3ef5a68db3108
- Result: confirmed crash
- Evidence:
  - exit code: 134
  - ERROR: AddressSanitizer: heap-buffer-overflow
  - WRITE of size 20046
  - crash function: CertFromX509
  - crash location: src/x509.c:11863
  - summary: heap-buffer-overflow in memcpy

## Fixed Release Verification

- Version: wolfSSL v5.9.1-stable
- Commit: 1d363f3adceba9d1478230ede476a37b0dcdef24
- Result: safe rejection
- Evidence:
  - wolfSSL_i2d_X509_bio returned 0
  - exit code: 1
  - NO_CRASH_SIGNAL
  - no ASan heap-buffer-overflow

## Current Version Verification

- Version description: v5.9.1-stable-1373-g8fca95ce6
- Commit: 8fca95ce651d6e370d91f5598786de4bc66aa2c2
- Result: safe rejection
- Evidence:
  - wolfSSL_i2d_X509_bio returned 0
  - exit code: 1
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

This PoC is a high-quality certificate-level historical vulnerability reproduction sample. It has PR-based trigger reconstruction, a concrete DER certificate input, vulnerable-version ASan heap-buffer-overflow evidence, fixed-release safe-rejection evidence, and current-version safe-rejection evidence.

## Recommended Usage

- discovery_seed: yes
- regression_test: yes
- x509_authority_key_identifier_memory_safety_seed: yes
- cross_library_migration_candidate: yes
- semantic_seed: limited
- negative_control: no
- documentation_only: no
