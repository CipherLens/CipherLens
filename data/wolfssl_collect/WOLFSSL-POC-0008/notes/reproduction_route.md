# WOLFSSL-POC-0008 Reproduction Route

## Selected Primary Route

Use the official test pattern introduced by commit 46f632038:

- test_tls13_pqc_hybrid_truncated_keyshare
- malicious TLS 1.3 ServerHello
- key_share extension with truncated hybrid key_exchange length
- group: WOLFSSL_SECP256R1MLKEM768
- key_exchange length: 10 bytes
- expected vulnerable failure: UAF / double-free during wolfSSL_free cleanup

## Why 46f632038 First

The patch summary explicitly states that the test covers a malicious server sending a truncated PQC hybrid KeyShare in ServerHello. Under ASan, the vulnerable cleanup path manifests as ForceZero writing to freed KyberKey memory during:

wolfSSL_free -> TLSX_FreeAll -> TLSX_KeyShare_FreeAll

This directly matches the CVE-2026-5460 description.

## Backup Route

If the truncated-keyshare test does not trigger on the selected build configuration, use e37118bdf hardening test. That test targets a dangling keyShareEntry->key after TLSX_KeyShare_ProcessPqcHybridClient internal cleanup and is designed to expose UAF/double-free in TLSX_KeyShare_FreeAll.

## Expected Version Boundary

- Vulnerable: wolfSSL v5.9.0-stable
- Fixed: wolfSSL v5.9.1-stable
