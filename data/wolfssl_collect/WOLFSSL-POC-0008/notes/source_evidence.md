# WOLFSSL-POC-0008 Source Evidence

## Official Vulnerability Description

wolfSSL official Security Vulnerabilities page lists CVE-2026-5460.

The described issue is a TLS 1.3 malicious server path where a truncated PQC hybrid KeyShare, for example P256_ML_KEM_512 with 10 bytes instead of the required 768+ bytes, reaches an error cleanup path that double-frees the KyberKey.

## Expected Version Boundary

- Vulnerable candidate: wolfSSL v5.9.0-stable
- Fixed candidate: wolfSSL v5.9.1-stable

## Initial Source Search Signals

Relevant source and git-history keywords:

- TLSX_KeyShare_ProcessPqcHybridClient
- TLSX_KeyShare_GenPqcKeyClient
- WOLFSSL_TLSX_PQC_MLKEM_STORE_OBJ
- MlKemKey / KyberKey
- P256_ML_KEM_512
- truncated KeyShare
- double-free cleanup path

High-priority candidate commits:

- 9467d82ae NULL the correct key in TLSX_KeyShare_ProcessPqcHybridClient when using WOLFSSL_TLSX_PQC_MLKEM_STORE_OBJ
- e37118bdf Hardening in TLSX_KeyShare_ProcessPqcHybridClient
- 46f632038 Fix PQC hybrid KeyShare pointer sanity
- 11d2f4894 Guard ProcessKeyShare against truncated key shares
