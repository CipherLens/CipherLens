# CMAC Double-Final Review

## Scope

This review checks whether repeated `EVP_MAC_final()` on CMAC is an unexpected
lifecycle success or an allowed provider/legacy CMAC behavior.

Artifacts:

- `artifacts/triage/mac_lifecycle_minimal/cases/cmac_multi_sequence_review.c`
- `artifacts/triage/mac_lifecycle_minimal/results/cmac_multi_algorithm_results.txt`

## Runtime Findings

Tested algorithms and sequences:

- `HMAC` + `SHA256`
- `HMAC` + `SHA512`
- `CMAC` + `AES-128-CBC`
- `CMAC` + `AES-256-CBC`
- `setup_update_final_final`
- `setup_final_final`
- `final_before_setup`
- `abort_then_final` (not executable for EVP_MAC because there is no explicit
  `EVP_MAC_abort()` API; using a freed context would be invalid harness misuse)

Observed behavior:

- HMAC repeated final:
  - first final succeeds
  - second final fails
  - `outl2` may still be modified or retain the previous digest length
- CMAC repeated final:
  - first final succeeds
  - second final also succeeds
  - `outl1=16`, `outl2=16` for both AES-128-CBC and AES-256-CBC
- `final_before_setup`:
  - returns failure for HMAC and CMAC
  - `outl` is modified on failure because `EVP_MAC_final()` copies an
    uninitialized local `l` after provider final failure
- ASan/UBSan:
  - no sanitizer crash was observed

## Source Evidence

`crypto/evp/mac_lib.c`:

- `EVP_MAC_final()` calls provider `final(ctx->algctx, out, &l, outsize)`.
- If `outl != NULL`, it copies local `l` into `*outl` regardless of provider
  success or failure.

`providers/implementations/macs/cmac_prov.c`:

- `cmac_final()` directly delegates to `CMAC_Final(macctx->ctx, out, outl)`.

`crypto/cmac/cmac.c`:

- `CMAC_Final()` does not set `ctx->nlast_block = -1` or otherwise mark the
  context as finalized.
- `CMAC_resume()` exists and reinitializes the cipher context so additional
  data can be processed after `CMAC_Final()`.

## Documentation Evidence

`doc/man3/CMAC_CTX.pod`:

- Documents a two-step `CMAC_Final()` usage: call once with `out == NULL` to get
  the output size, then call `CMAC_Final()` again with an allocated output
  buffer.
- Documents `CMAC_resume()` as resuming a previously finalized CMAC calculation.

`doc/man7/life_cycle-mac.pod`:

- Lists `EVP_MAC_final` as a transition from `updated` to `finaled`.
- Does not list ordinary `EVP_MAC_final` as a legal transition from `finaled`.

`doc/man3/EVP_MAC.pod`:

- States that the MAC lifecycle will be enforced in the future.
- This implies current implementations may not consistently enforce the formal
  lifecycle.

## Classification

Final classification:

`allowed_legacy_cmac_semantics_with_evp_lifecycle_mismatch`

Report as:

- CMAC provider permits repeated final because legacy `CMAC_Final()` permits
  repeated final-style usage and does not mark the context finalized.
- This differs from HMAC behavior and from the generic `EVP_MAC` lifecycle
  table, so it is a useful lifecycle semantic divergence.
- It should not be reported as a vulnerability without a concrete caller impact.

Recommended next step:

- If this is pursued further, test whether any caller assumes repeated
  `EVP_MAC_final()` must fail after finalization.
- Otherwise, keep it as a negative/triage example for lifecycle oracle design.
