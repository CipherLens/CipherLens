# WOLFSSL-POC-0003

## Summary

This directory stores CVE-2026-5448, a wolfSSL X.509 date parsing buffer overflow candidate involving the OpenSSL compatibility APIs wolfSSL_X509_notAfter and wolfSSL_X509_notBefore.

## Basic Information

- PoC ID: WOLFSSL-POC-0003
- Source library: wolfSSL
- CVE: CVE-2026-5448
- Bug class: X.509 date parsing buffer overflow
- Harness family: x509_date_parser_memory_safety
- Oracle type: crash_sanitizer_oracle

## Current Status

- Original input collected: false
- Input reconstructed: false
- Vulnerable version verified: false
- Fixed version verified: false
- Current version verified: false
- Current quality level: Q2_candidate_pending_input_reconstruction

## Planned Version Matrix

| Version | Role | Expected Result |
|---|---|---|
| wolfSSL v5.9.0-stable | candidate vulnerable version | sanitizer crash expected |
| wolfSSL v5.9.1-stable | candidate fixed version | safe handling expected |
| current wolfSSL | current version | safe handling expected |

## Next Steps

1. Fetch and inspect wolfSSL PR 10071.
2. Identify the exact date parsing boundary condition.
3. Reconstruct a malformed X.509 certificate with crafted notBefore / notAfter field.
4. Build wolfSSL v5.9.0-stable with ASan/UBSan.
5. Write minimal harness calling wolfSSL_X509_notAfter and wolfSSL_X509_notBefore.
6. Test v5.9.0-stable, v5.9.1-stable, and current wolfSSL.
