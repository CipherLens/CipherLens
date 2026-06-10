# WOLFSSL-POC-0008 Candidate Selection

## Selected Candidate

- Candidate PoC ID: WOLFSSL-POC-0008
- CVE: CVE-2026-5460
- Module family: TLS 1.3 / PQC hybrid key exchange
- Bug class: error cleanup path double-free
- Expected trigger surface:
  - TLS 1.3 client processing malicious ServerHello
  - truncated PQC hybrid KeyShare
  - example group: P256_ML_KEM_512
- Expected vulnerable object:
  - KyberKey / ML-KEM key object
- Expected fixed version:
  - wolfSSL v5.9.1-stable

## Selection Rationale

This candidate is selected to add a cleanup-path memory safety sample to the dataset.

The existing dataset already covers X.509, DTLS 1.3 ACK serialization, and PKCS7/CMS parsing/encoding. CVE-2026-5460 adds a different vulnerability family: TLS 1.3 error cleanup and double-free in a post-quantum hybrid KeyShare path.

## Expected Trigger Shape

- Build wolfSSL with TLS 1.3 and PQC/ML-KEM hybrid group support.
- Run a TLS 1.3 client path.
- Simulate or inject a malicious ServerHello containing a truncated hybrid KeyShare.
- Use a group such as P256_ML_KEM_512.
- Force the key share parse failure path.
- Observe whether cleanup double-frees KyberKey under ASan.

## Initial Quality Status

- Status: candidate selected
- Vulnerable version: pending
- Fixed version: pending
- Current version: pending
