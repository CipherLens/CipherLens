# MBEDTLS-POC-0005: CVE-2025-48965

## Basic information

- Source: CVE-2025-48965
- URL: https://lists.debian.org/debian-lts-announce/2025/08/msg00013.html | https://github.com/Mbed-TLS/mbedtls-docs/blob/main/security-advisories/mbedtls-security-advisory-2025-06-6.md | https://mbed-tls.readthedocs.io/en/latest/tech-updates/security-advisories/
- PoC type: memory_safety
- Primary module: asn1write
- Target function: mbedtls_asn1_store_named_data
- Failure signal: NULL pointer dereference

## Root cause

Missing validation for conflicting ASN.1 named-data value pointer and nonzero length, allowing NULL pointer dereference.

## Mutation point

library/asn1write.c: mbedtls_asn1_store_named_data(), validation of val.p == NULL with val.len > 0.

## Buggy behavior

conflicting val.p NULL and val.len > 0 state can cause NULL dereference

## Fixed behavior

invalid ASN.1 named-data state is rejected or handled safely

## Regression test / PoC extraction plan

- Candidate test file: `tests/.gitignore`
- Step 1: Inspect listed test files and identify the exact regression test case.
- Step 2: Extract a minimal input or API call sequence that triggers the buggy behavior.
- Step 3: Record build version, run command, and observed failure signal.
- Step 4: Map the triggering code to AST-level mutation points.

## Reproduction status

- Current status: reconstructable
- Local reproduction command: TBD
- Buggy version/commit: TBD
- Fixed version/commit: TBD

## Notes

CVE advisory has clear NULL dereference semantics, but commit/file evidence is broad; needs fixing commit narrowing. | Upgraded from maybe; clear ASN.1 named-data NULL pointer root cause. CVE advisory identifies mbedtls_asn1_store_named_data(); searched commits include Fix bug in mbedtls_asn1_store_named_data() and related unit tests. Exact fixing commit should still be confirmed during reproduction.
