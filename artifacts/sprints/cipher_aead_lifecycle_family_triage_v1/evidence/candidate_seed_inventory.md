# Candidate Seed Inventory

## Summary

The local pattern bank and RAG sources identify four useful seeds for
`cipher_aead_lifecycle`:

| Seed | Library | Pattern | Evidence Quality | Recommended Path |
| --- | --- | --- | --- | --- |
| `MBEDTLS-POC-0004` | mbedTLS | invalid padding output length on finalization | medium | `A_recipe_slot_cross_library_migration` |
| `MBEDTLS-POC-0028` | mbedTLS | AEAD tag length validation / unexpected success | medium | `B_controlled_family_mutation` |
| `OPENSSL-ISSUE-17715` | OpenSSL | incomplete init followed by update path | weak | `D_crash_sanitizer_evidence_audit` |
| `OPENSSL-ISSUE-8980` | OpenSSL | EVP AES-GCM context copy / uninitialized state | medium | `D_crash_sanitizer_evidence_audit` |

## Interpretation

This inventory is enough to enter a controlled mutation-planning sprint. It is
not enough to claim a new vulnerability. The safest next path is B-path
same-family mutation, while preserving A-path feasibility for mbedTLS PSA/GCM/CCM
to OpenSSL EVP AEAD mappings.
