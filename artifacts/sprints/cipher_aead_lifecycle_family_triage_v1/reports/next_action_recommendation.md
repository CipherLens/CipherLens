# Next Action Recommendation

## Recommendation

Enter:

```text
cipher_aead_lifecycle_mutation_v1
```

The next sprint should render and run a compact controlled mutation matrix using
the draft cases from this triage.

## D Audit

Do a targeted D-path audit only for crash/sanitizer seeds:

- `OPENSSL-ISSUE-17715`
- `OPENSSL-ISSUE-8980`

Do not block the whole family on those audits.

## A-Path Recipe Preparation

Prepare A-path adapter recipes after B-path controls clarify expected behavior.
The first A-path candidates should focus on:

- mbedTLS PSA AEAD setup/update/finish/verify
- OpenSSL EVP GCM/CCM init/update/final/tag controls

## Blockers

- Mode-specific expected-oracle rules for GCM vs CCM.
- Compact normal encryption/decryption controls.
- Clarify whether `MBEDTLS-POC-0004` belongs in this broad family or should stay
  under `return_code_outlen_semantic`.
- D-path audit before using OpenSSL crash artifacts as strong evidence.
