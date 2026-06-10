# CMAC Lifecycle Documentation Review

## Scope

This review compares OpenSSL 3.5.5 `EVP_MAC_final()` / CMAC behavior with
mbedTLS 4.1.0 PSA `psa_mac_sign_finish()` behavior for repeated finalization.

## OpenSSL Findings

Evidence:

- `crypto/evp/mac_lib.c:186`: `EVP_MAC_final()` delegates directly to the
  provider `final` function through `evp_mac_final()`.
- `providers/implementations/macs/cmac_prov.c:199`: the CMAC provider final
  callback delegates directly to `CMAC_Final(macctx->ctx, out, outl)`.
- `crypto/cmac/cmac.c:247`: `CMAC_Final()` computes output but does not mark the
  context as finaled or inactive.
- `crypto/cmac/cmac.c:278`: `CMAC_resume()` exists for continuing a finalized
  CMAC calculation.
- `doc/man3/CMAC_CTX.pod:78`: `CMAC_Final()` may be called once with `out=NULL`
  to get the length and again with an allocated output buffer.
- `doc/man3/CMAC_CTX.pod:85`: `CMAC_resume()` resumes a previously finalized
  CMAC calculation, allowing additional data and a new MAC.
- `doc/man7/life_cycle-mac.pod` describes a generic MAC `finaled` state, but it
  does not by itself prove that provider-specific CMAC rejects repeated final.

Observed minimal behavior:

- For both AES-128-CBC and AES-256-CBC CMAC, OpenSSL returns success for the
  first and second `EVP_MAC_final()`.
- The first and second outputs differ.
- `EVP_MAC_update()` after the second final also succeeds.
- A third `EVP_MAC_final()` succeeds.

Interpretation:

OpenSSL CMAC behavior appears consistent with CMAC legacy/provider semantics
that permit finalization followed by continued operation, especially given
`CMAC_resume()` documentation and implementation. This should be treated as
`allowed_legacy_semantics_needs_review`, not a confirmed bug.

## mbedTLS PSA Findings

Evidence:

- `tf-psa-crypto/include/psa/crypto.h:1516`: applications finish a MAC operation
  by calling `psa_mac_sign_finish()`.
- `tf-psa-crypto/include/psa/crypto.h:1526`: after setup, an operation must be
  terminated by successful `psa_mac_sign_finish()` or `psa_mac_abort()`.
- `tf-psa-crypto/include/psa/crypto.h:1699`: `psa_mac_sign_finish()` returns
  `PSA_ERROR_BAD_STATE` if the operation state is not an active MAC sign
  operation.
- `tf-psa-crypto/core/psa_crypto.c:2829`: `psa_mac_sign_finish()` checks
  operation activity and sign mode before finishing.
- `tf-psa-crypto/core/psa_crypto.c:2888`: on exit, the function calls
  `psa_mac_abort(operation)`, making the operation inactive after success.

Observed minimal behavior:

- For both AES-128 and AES-256 CMAC, the first `psa_mac_sign_finish()` succeeds.
- The second `psa_mac_sign_finish()` returns `-137`, corresponding to
  `PSA_ERROR_BAD_STATE`.
- `psa_mac_abort()` after the terminated operation is safe and returns success.

Interpretation:

mbedTLS PSA behavior is consistent with a one-shot active operation lifecycle:
after a successful finish, a second finish is rejected as bad state.

## Overall Classification

Current classification:

```text
lifecycle_semantic_divergence_candidate
```

Not classified as:

```text
crash_candidate
confirmed_bug
CVE_candidate
```

Reason:

The observed behavior is a semantic lifecycle divergence between OpenSSL CMAC
provider behavior and mbedTLS PSA operation-state rules. OpenSSL has source and
documentation evidence suggesting CMAC final/resume semantics may intentionally
allow continued operation. The remaining question is whether the `EVP_MAC`
generic lifecycle documentation should constrain provider CMAC repeated final
more strictly than the legacy CMAC semantics do.
