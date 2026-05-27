# MBEDTLS-POC-0011: CVE-2025-52497

## Basic information

- Source: CVE-2025-52497
- URL: https://lists.debian.org/debian-lts-announce/2025/08/msg00013.html | https://github.com/Mbed-TLS/mbedtls-docs/blob/main/security-advisories/mbedtls-security-advisory-2025-06-2.md
- PoC type: memory_safety
- Primary module: pem
- Target function: mbedtls_pem_read_buffer
- Failure signal: one-byte heap buffer underflow

## Root cause

Missing PEM parse bounds check causing one-byte heap-based buffer underflow on untrusted PEM input.

## Mutation point

library/pem.c: mbedtls_pem_read_buffer(), boundary check around PEM buffer parsing and empty PEM content handling.

## Buggy behavior

empty or malformed PEM content can trigger one-byte underflow

## Fixed behavior

PEM parser rejects empty/malformed contents before unsafe access

## Regression test / PoC extraction plan

- Candidate test file: `tests/include/alt-dummy/aes_alt.h`
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

CVE advisory explicitly names PEM underflow, but commit/file evidence is broad; needs fixing commit narrowing. | Upgraded from maybe; clear PEM parser heap-buffer-underflow root cause. Focused evidence includes pem: reject empty PEM contents and related PEM parser tests. Exact fixing commit should still be confirmed during reproduction.
