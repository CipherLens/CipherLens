# OPENSSL-ISSUE-19524: Public-Only ED25519 Key Sign NULL Dereference

## Basic Information

- Pattern ID: OPENSSL-ISSUE-19524
- Template ID: PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF
- Source issue: https://github.com/openssl/openssl/issues/19524
- Title: ED25519_sign and ED448_sign missing check for private_key leading to segfault
- Component: PKEY/ED25519/ED448
- Affected versions: OpenSSL 3.0.2, OpenSSL 1.1.1r
- CVE: None assigned
- Strict reproduction: false (RAG-seed harness; not strict reproduction)

## Root Cause

`EVP_DigestUpdate()` and the ED25519/ED448 sign implementation allow NULL private
key material to be passed. When a public-only `EVP_PKEY` (created via
`EVP_PKEY_new_raw_public_key`) is passed to `EVP_DigestSignInit` / `EVP_DigestSign`,
the signing path dereferences a NULL private key pointer in the affected versions.

## Core Vulnerability Path

```
EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, ...)   ← public-only key
    ↓
EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey)       ← may accept or reject
    ↓
EVP_DigestSign(ctx, sig, &siglen, msg, msglen)        ← bug: NULL deref on private key
    ↓
SEGV / NULL dereference (affected versions)
safe reject (fixed versions)
```

## Buggy vs Safe Behavior

| | Buggy (3.0.2, 1.1.1r) | Safe (3.0.13+) |
|---|---|---|
| EVP_DigestSignInit | accepts public-only key | may reject or accept |
| EVP_DigestSign | NULL deref / SEGV | returns != 1 with error |
| Oracle signal | ASAN/UBSAN/exit139 | controlled error return |

## Migration to mbedTLS / PSA

The PSA Crypto API is the strongest migration target:
- `psa_import_key` with `PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)`
  and no `PSA_KEY_USAGE_SIGN_MESSAGE` flag
- `psa_sign_message` attempt
- PSA must return `PSA_ERROR_NOT_PERMITTED` or `PSA_ERROR_INVALID_ARGUMENT` safely

This preserves the **capability mismatch** oracle:
public-only key must not be able to sign, and the library must not crash.

## Pattern YAML

`knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-19524.yaml`
