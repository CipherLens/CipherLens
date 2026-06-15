# Execution Route Decision

## Decision

```text
proposed_execution_path: B_controlled_family_mutation
fallback_path: D_then_A
```

## Why B First

The family has strong state-machine structure, but cross-library mapping is not
yet recipe-slot precise. B-path lets the project isolate lifecycle sequences,
controls, tag timing, and return-code/output-state oracles before introducing
adapter complexity.

## A-Path Feasibility

A-path is feasible later because both sides expose AEAD lifecycle APIs:

- OpenSSL EVP: init, AAD update, data update, final, tag set/get, cleanup.
- mbedTLS PSA/GCM/CCM: setup, AAD update, data update, finish/verify, cleanup.

However, GCM and CCM ordering rules differ, and tag handling must be encoded in
strict adapter recipes.

## D-Path Role

`OPENSSL-ISSUE-17715` and `OPENSSL-ISSUE-8980` should be treated as targeted
crash/sanitizer evidence-audit seeds, not as immediate confirmed discoveries.

## C-Path Role

Current evidence is API-level rather than CLI/app-level, so C-path is not the
primary route for this sprint.
