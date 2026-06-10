# Framework Drift Risk Report

## Assessment

Risk level: medium.

The project still follows the original research design, but there is a real drift risk if seed validation stops before pattern expansion.

## Current Drift Points

- `secure_heap_state_lifecycle_v1` can look like historical issue reproduction because it starts from `OPENSSL-ISSUE-28669` and validates `CRYPTO_secure_used()` crash behavior.
- Several renderers/analyzers are still family-specific scripts.
- Version novelty classification is not yet fully integrated into scheduler decisions.
- Large generated artifacts and logs can blur which files are framework evidence versus disposable run output.

## Why Secure Heap Is Still Useful

It extracts a reusable state lifecycle oracle, validates initialized controls, records crash/precondition behavior, and establishes version provenance. That is seed validation and oracle calibration, not a final vulnerability claim.

## When It Becomes Discovery Again

It returns to the discovery framework when the seed expands into:

- same-family secure heap API/state matrix,
- cross-version regression/current-version classification,
- analogous lifecycle oracle testing across other libraries.

## Required Correction

The scheduler should treat seed validation as an intermediate state that must flow into pattern expansion before any “new candidate discovery” claim is made.
