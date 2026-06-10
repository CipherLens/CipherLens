# Family Rerank After AEAD-GCM

AEAD-GCM lifecycle cases are now negative feedback, so the scheduler should avoid continuing the three closed GCM candidates as vulnerability candidates.

## Top Recommendations

1. `asn1_nested_boundary` — priority `0.82`. Best next family because it has concrete historical seeds and a distinct oracle surface from the closed GCM legal-semantics cases. Suggested path: `D_then_A`.
2. `evp_pkey_context_lifecycle` — priority `0.76`. Promising lifecycle/state family, but should begin with D-path reproduction because behavior is likely version-specific.
3. `cipher_aead_lifecycle_ctx_copy` — priority `0.70`. Keeps non-GCM AEAD space alive, especially `ctx_copy_or_reset`, while explicitly excluding closed GCM final/tag-length cases.

## Lower Priority / Defer

- `cipher_aead_lifecycle_ccm`: still available, but only if the mutation matrix is CCM-specific.
- `pkey_verify_semantic`: useful but likely to need a stricter semantic oracle.
- `provider_fetch_lifecycle` and `ossl_store_decoder_boundary`: need seed inventory and D-path audit first.
- `bn_error_path`: stable baseline but less novel right now.
