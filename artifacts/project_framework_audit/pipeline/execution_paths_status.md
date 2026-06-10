# Execution Paths Status

## A-path: Recipe-Slot Cross-Library Migration

Purpose: structured cross-library API migration with strict GLM/LLM `slot_bindings`, `adapter_validate`, template rendering, `compile_run`, and generic analysis.

Completed example: MAC lifecycle under `artifacts/migrations/mac_lifecycle_glm_full_a_path/`.

Status: full A-path compliant. It records 8 run-ok cases, 4 OpenSSL/mbedTLS pairs, 2 `migrated_safe` pairs, and 2 `migration_needs_triage` pairs. The triage cases are semantic divergence around repeated-final and update-after-final, not vulnerability claims.

## B-path: Controlled Family Mutation

Purpose: deterministic family-level matrix expansion when the mutation dimensions are known.

Current example: `secure_heap_state_lifecycle_v1` is D-then-B seed validation / oracle calibration. It is not cross-library migration and not final discovery.

Remaining gap: family renderers and analyzers should converge on a common interface instead of growing as independent scripts.

## C-path: App-Level Validation Gap

Purpose: test app/CLI behavior with output artifacts, stderr, exit status, and malformed-input controls.

Completed example: DER full-consumption v2 under `artifacts/sprints/der_full_consumption_v2/`. It has 75 cases and 30 `app_level_validation_gap_candidate` observations.

This is semantic validation-gap triage, not a crash or CVE claim.

## D-path: Crash/Sanitizer Evidence Audit

Purpose: verify crash logs, sanitizer signals, version evidence, and harness validity before promotion.

Completed example: crash/sanitizer top5 audit. `OPENSSL-ISSUE-28669` was promoted as a secure heap lifecycle seed because local evidence includes SIGSEGV / exit 139 / invalid-read style evidence.

## Secure Heap Boundary

`secure_heap_state_lifecycle_v1` must now move to pattern expansion. Stopping at 28669 reproduction would create historical-reproducer drift; expanding same-family APIs, versions, and state combinations brings it back into the discovery framework.
