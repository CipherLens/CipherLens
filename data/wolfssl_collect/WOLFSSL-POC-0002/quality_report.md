# PoC Quality Report

## Basic Information

- PoC ID: WOLFSSL-POC-0002
- Source library: wolfSSL
- Issue / CVE: CVE-2017-2800 / TALOS-2017-0293 / EDB-41984
- Title: wolfSSL 3.10.2 X.509 certificate text parsing off-by-one
- Bug class: X.509 certificate text parsing off-by-one / out-of-bounds byte overwrite
- Harness family: x509_text_field_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Input Quality

- Has original bug-triggering input: false
- Uses placeholder input: false
- Input provenance: reconstructed_from_exploitdb_talos_poc_command
- Input files:
  - inputs/reconstructed/cve-2017-2800-cert1.pem
  - inputs/reconstructed/cve-2017-2800-cert1.der
  - inputs/reconstructed/generated_from_exploitdb_command/cert1.pem
  - inputs/reconstructed/generated_from_exploitdb_command/key.pem

## Reproduction Status

- Vulnerable version verified: true
- Fixed version verified: false
- Current version verified: false
- Original failure signal preserved: true
- Strict reproduction: true
- Note: strict reproduction is based on the public PoC generation command, not original attachment bytes.

## Successful Reproduction Environment

- wolfSSL version: v3.10.2-stable
- Build mode: ASan/UBSan, debug, -O0
- Configure options:
  - --enable-debug
  - --enable-opensslextra

## Evidence

ASan evidence:

- ERROR: AddressSanitizer: stack-buffer-overflow
- WRITE of size 1
- wolfSSL_X509_NAME_get_text_by_NID src/ssl.c:12471
- localityName stack buffer overflow
- Exit code: 134

Relevant call path:

- main, poc/poc_certfields_min.c
- wolfSSL_X509_NAME_get_text_by_NID, src/ssl.c

## Quality Level

Current quality level:

Q1_strict_reproduction_candidate

## Reason

This PoC has a public PoC generation command, a reconstructed trigger certificate, a minimal harness, an accurate vulnerable version, and a preserved sanitizer failure signal. The reproduced failure matches the reported root cause: a trailing NUL write one byte past a fixed-size localityName buffer in wolfSSL_X509_NAME_get_text_by_NID.

## Recommended Usage

- discovery_seed: yes
- regression_test: yes
- cross_library_migration: yes
- semantic_seed: no
- negative_control: no
- documentation_only: no

## Missing Evidence

- Original attached certificate bytes, if available.
- Fixed release or fixed commit verification.
- Current version verification.
- Release-level version matrix.

## Version Matrix Status

- Vulnerable version verified: true
- Fixed release verified: true
- Current version verified: true
- Exact fixed commit identified: false
- Release-level fixed boundary:
  - vulnerable: v3.10.2-stable
  - fixed release candidate: v3.11.0-stable

## Final Quality Judgment

Current quality level:

Q1_strict_reproduction_candidate

This PoC is a high-quality historical vulnerability reproduction sample. It has a public PoC generation command, reconstructed trigger certificate, vulnerable-version ASan stack-buffer-overflow evidence, fixed-release safe-execution evidence, and current-version safe-execution evidence.
