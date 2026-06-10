# wolfSSL PoC Inventory

| PoC ID | CVE / Issue | Bug Class | Input Provenance | Quality | Vulnerable | Fixed | Current |
|---|---|---|---|---|---|---|---|
| WOLFSSL-POC-0001 | GitHub issue #2555 | X.509 certificate parsing heap-buffer-overflow | original_issue_attachment | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0002 | CVE-2017-2800 / TALOS-2017-0293 / EDB-41984 | X.509 certificate text parsing off-by-one out-of-bounds byte overwrite | reconstructed_from_exploitdb_talos_poc_command | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0003 | CVE-2026-5448 | X.509 date parsing buffer overflow | reconstructed_from_pr_10071_official_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0004 | CVE-2026-5447 | X.509 AuthorityKeyIdentifier heap buffer overflow | reconstructed_from_pr_10112_official_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0005 | CVE-2026-5264 | DTLS 1.3 ACK record processing heap buffer overflow | reconstructed_from_official_pr_10076_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0006 | CVE-2026-0819 | PKCS7 SignedData encoding out-of-bounds write | reconstructed_from_official_security_advisory_and_source_patch | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0007 | CVE-2026-5295 | PKCS7 ORI OID processing stack buffer overflow | reconstructed_from_official_pr_10116_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0008 | CVE-2026-5460 | TLS 1.3 PQC hybrid KeyShare error cleanup double-free | reconstructed_from_official_46f632038_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0009 | CVE-2026-2646 | SSL_SESSION deserialization heap-buffer-overflow | reconstructed_from_official_session_deserialization_test_pattern | Q1_strict_reproduction_candidate | True | True | True |
| WOLFSSL-POC-0010 | CVE-2026-3547 | TLS ALPN extension parsing out-of-bounds read | reconstructed_from_official_select_next_proto_fix_pattern | Q1_strict_reproduction_candidate | True | True | True |

## Summary

- Total collected wolfSSL PoCs: 10
- Q1 strict reproduction candidates: 10
- Vulnerable-version verified: 10
- Fixed-version verified: 10
- Current-version verified: 10
