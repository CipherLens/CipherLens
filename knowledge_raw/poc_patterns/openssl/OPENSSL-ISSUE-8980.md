# OPENSSL-ISSUE-8980: EVP_CIPHER_CTX_copy Uninitialized State (AES-GCM)

## Basic Information

- Pattern ID: OPENSSL-ISSUE-8980
- Template ID: EVP_CIPHER_CTX_COPY_UNINIT_STATE
- Source issue: https://github.com/openssl/openssl/issues/8980
- Title: OpenSSL 1.0.2 branch on uninitialized memory in EVP_CIPHER_CTX_copy
- Component: EVP/AES_GCM
- Affected version: OpenSSL 1.0.2
- State: closed (maintainer declined to fix in 1.0.2)
- CVE: None assigned
- Strict reproduction: false

## Root Cause

In OpenSSL 1.0.2, calling `EVP_CIPHER_CTX_copy` on an AES-GCM context that has been
associated with the cipher algorithm via `EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)`
but has **not** received a key or IV triggers access to uninitialized memory.

The internal GCM state (`EVP_AES_GCM_CTX` / `gcm128_context`) is allocated during
`EVP_EncryptInit_ex`, but certain internal pointers within this structure may remain
uninitialized until the key and IV are set. The `EVP_CIPHER_CTX_copy` path in 1.0.2
does not guard against this partially-initialized state, resulting in an
uninitialized-memory read or NULL dereference.

**Root cause confidence:** partial. The fix diff has not been reviewed. Root cause
is inferred from maintainer statement ("probably just a bug") and Valgrind-observable
behavior on affected versions.

## Core Vulnerability Path

```
EVP_CIPHER_CTX_new()                       → allocate source context
EVP_aes_128_gcm()                          → get cipher descriptor
EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)  → associate cipher, no key, no IV
EVP_CIPHER_CTX_new()                       → allocate destination context
EVP_CIPHER_CTX_copy(ctx2, ctx)             → CRASH: copy of partially-initialized GCM state
```

The defining characteristic is the **copy operation on a stateful GCM context**
that has not completed initialization (no key, no IV).

## Buggy vs Safe Behavior

| Observable | OpenSSL 1.0.2 (buggy) | OpenSSL 3.x (safe/fixed) |
|---|---|---|
| EVP_CIPHER_CTX_copy return | crash / uninitialized read | returns 1 (success) |
| Valgrind signal | uninitialized memory read | 0 errors |
| ASAN signal | invalid read | none |
| Exit code | non-zero / 139 | 0 |

**Current local validation (OpenSSL 3.0.13):** compiled and executed with 0 Valgrind errors.
This is expected safe/fixed behavior on modern OpenSSL. Not a strict reproduction.

## Oracle

```
oracle_type: crash_sanitizer_oracle
bug signals:
  - ASAN/UBSAN/Valgrind uninitialized memory read during EVP_CIPHER_CTX_copy
  - SEGV / exit code 139
safe signals:
  - EVP_CIPHER_CTX_copy returns 1 without sanitizer signal
  - Normal program exit
```

## Mutation Points

1. `CIPHER_ALGORITHM`: AES-128-GCM vs AES-256-GCM vs AES-128-CCM
2. `SRC_CTX_INIT_STATE`: no key/IV (trigger), key only, IV only, full init
3. `COPY_CALL_ORDER`: copy before key/IV, after key only, after full init
4. `DST_CTX_INIT_STATE`: fresh destination context vs previously used context

## Migration Applicability

**Status: migration_not_applicable**

The core vulnerability path requires `EVP_CIPHER_CTX_copy` — an API that copies
a stateful cipher context. **mbedTLS does not expose a public cipher context copy
API in either the legacy cipher layer (mbedtls_cipher_context_t) or the PSA AEAD
operation layer.**

Without a context copy API, the defining vulnerability path cannot be expressed
in any mbedTLS harness. See candidates.yaml for full scoring.

## References

- Issue: https://github.com/openssl/openssl/issues/8980
- Artifact: datasets/openssl/poc_artifacts/issue_8980/
- Pattern YAML: knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.yaml
