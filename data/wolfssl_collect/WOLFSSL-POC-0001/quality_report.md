# PoC Quality Report

## Basic Information

- PoC ID: WOLFSSL-POC-0001
- Source library: wolfSSL
- Issue / CVE: GitHub issue #2555
- Title: Heap based buffer overflow while parsing crafted X.509 certificates
- Bug class: X.509 / ASN.1 certificate parsing memory safety
- Harness family: x509_asn1_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Input Quality

- Has original bug-triggering input: true
- Uses placeholder input: false
- Input provenance: original_issue_attachment
- Input files:
  - inputs/original/crash_000_FreeDecodedCert.zip
  - inputs/original/crash_000_FreeDecodedCert.pem

## Reproduction Status

- Vulnerable version verified: true
- Fixed version verified: false
- Current version verified: false
- Original failure signal preserved: true

## Successful Reproduction Environment

- wolfSSL version: v4.2.0-stable
- Commit: 48c4b2fedcee4d61b6a76c5ce9e33ab212d6ab4a
- Build mode: ASan/UBSan, debug, -O0
- Important configure options:
  - --enable-debug
  - --enable-dtls
  - --enable-opensslextra
  - --enable-certgen
  - --enable-certreq
  - --enable-certext

## Evidence

UBSan evidence:

- wolfcrypt/src/asn.c:5121:27: runtime error: index 19 out of bounds for type 'int [19]'

ASan evidence:

- ERROR: AddressSanitizer: SEGV
- Crash occurs during FreeDecodedCert
- Exit code: 134

Relevant call path:

- GetName
- wc_GetPubX509
- DecodeToKey
- ProcessBuffer
- ProcessFile
- wolfSSL_CTX_use_certificate_chain_file
- FreeDecodedCert
- wolfSSL_Free
- free

## Quality Level

Current quality level:

Q1_strict_reproduction_candidate

## Reason

This PoC has the original crafted certificate, an accurate vulnerable version, a preserved sanitizer failure signal, and a concrete crash stack. The reproduced failure matches the reported root cause: an out-of-bounds write to DecodedName.loc followed by a crash during FreeDecodedCert.

## Recommended Usage

- discovery_seed: yes
- regression_test: yes
- cross_library_migration: yes
- semantic_seed: no
- negative_control: no
- documentation_only: no

## Missing Evidence

- Identify the exact fixed commit or fixed release.
- Run the same input on the fixed version.
- Run the same input on the current wolfSSL version.
- Build a minimal C harness if needed for later automated runner integration.
- Migrate the abstract pattern to OpenSSL and mbedTLS X.509 parsing APIs.

## Version Matrix Status

- Vulnerable version verified: true
- Fixed release verified: true
- Current version verified: true
- Exact fixed commit identified: false
- Release-level fixed boundary:
  - vulnerable: v4.2.0-stable
  - fixed release candidate: v4.3.0-stable
- Candidate commit 88bf5d967:
  - tested
  - still vulnerable
  - not an effective fix for this PoC

## Final Quality Judgment

Current quality level:

Q1_strict_reproduction_candidate

This PoC is a high-quality historical vulnerability reproduction sample. It has original malformed input, sanitizer-confirmed vulnerable-version crash evidence, fixed-release safe-reject evidence, and current-version safe-reject evidence.
