# Framework Alignment Final Report

## Framework Status

The framework remains aligned with the original research goal, but only
partially:

```text
historical pattern guided cross-library / cross-version / same-family
vulnerability candidate discovery
```

The main risk is stopping at historical issue reproduction. The secure heap work
must therefore continue into pattern expansion.

## Completed Representatives

- MAC lifecycle: full A-path compliant. It ran GLM slot filling,
  `adapter_validate`, cross-generator, rendering, `compile_run`, and generic
  analysis.
- DER full-consumption: C-path app-level validation-gap triage. It is semantic
  validation evidence, not a crash claim.
- secure_heap_state_lifecycle_v1: D-then-B seed validation and oracle
  calibration. It is not cross-library migration and not final discovery.

## secure_heap Version Provenance

The current secure heap sprint uses:

```text
OpenSSL 3.5.5 27 Jan 2026
```

Evidence:

- `run.jsonl` compile commands use `openssl-3.5.5/include` and
  `openssl-3.5.5` library path.
- Version probe reports header and runtime OpenSSL 3.5.5.
- `ldd` does not show `libcrypto.so`, and the local tree provides
  `libcrypto.a`, so linkage is static archive linkage into the executable.

## Historical Issue Version

Local artifact evidence for `OPENSSL-ISSUE-28669` records validation against:

```text
OpenSSL 3.0.13 / libcrypto.so.3
```

It does not identify:

- original reported version
- affected version range
- fixed version
- patch commit

Therefore historical overlap cannot be determined from local artifacts.

## Novelty Classification

```text
current_version_robustness_candidate_with_unknown_historical_overlap
```

This is not simply proven historical reproduction, because the current actual
version is OpenSSL 3.5.5. It is not a proven regression candidate because no
fixed version or patch commit is known locally.

Claim boundary:

```text
can_claim_new_vulnerability: false
can_claim_new_candidate: true
```

## Why secure_heap Is Not Full Migration

`secure_heap_state_lifecycle_v1` does not map a source-library PoC to a target
library API through recipe-slot adapters. It validates a same-library state
lifecycle oracle for OpenSSL secure heap APIs. It is useful seed validation, but
not the final contribution.

## Next Stage Pattern Expansion

The next stage should move from seed validation to discovery:

1. OpenSSL same-family API expansion across secure heap query, allocation, free,
   done, and reinit paths.
2. OpenSSL cross-version expansion across all available clean source versions.
3. Cross-library analogous lifecycle oracle for PSA / Botan / wolfSSL / LibreSSL
   lifecycle boundaries, without forcing `CRYPTO_secure_used` equivalence.

## Continue Other PoCs

Yes. Continue expanding other PoCs through their appropriate A/B/C/D paths, but
keep the evidence boundary explicit: safe/safe is valid, semantic divergence is
not automatically a vulnerability, and crash evidence must remain explicit.
