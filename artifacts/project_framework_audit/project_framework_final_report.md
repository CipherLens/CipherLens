# Project Framework Final Report

## One-Sentence Definition

This project is a historical PoC/root-cause driven cross-library, cross-version, and same-family vulnerability-pattern migration and new-candidate discovery framework.

## Current Pipeline

```text
Historical PoC / issue / patch
  -> root cause / mutation point / oracle extraction
  -> Pattern Bank
  -> RAG evidence
  -> Candidate triage / Scheduler
  -> Execution path planner
  -> A/B/C/D paths
  -> Render / Compile / Run / Analyze
  -> Feedback Store
  -> Pattern Expansion
```

## A/B/C/D Paths

- A-path: strict GLM recipe-slot cross-library migration.
- B-path: controlled family mutation sprint.
- C-path: app-level validation-gap triage.
- D-path: crash/sanitizer evidence audit before promotion.

## Representative Results

- MAC lifecycle: full A-path example. It used GLM slot filling, `adapter_validate`, cross generator, render, compile/run, and generic analysis.
- DER full-consumption: C-path app-level validation-gap example. It is semantic validation evidence, not a crash/CVE claim.
- `secure_heap_state_lifecycle_v1`: D-then-B seed validation and robustness qualification. It is not cross-library migration and not final discovery.

## Where The Project Works

- The A-path is now proven end-to-end.
- RAG, pattern bank, scheduler, and feedback artifacts are connected.
- C-path and D/B-path give useful alternatives when a PoC does not fit recipe-slot API migration.
- The framework now distinguishes safe results, semantic divergence, robustness candidates, and confirmed vulnerability boundaries.

## Drift Risk

The main risk is stopping after reproducing a historical-looking crash. `secure_heap_state_lifecycle_v1` avoids that only if the next step is pattern expansion across APIs, versions, and state combinations.

## Discovery Direction

The next work should not be “run more PoCs blindly.” It should classify families first, extract oracle/root cause, choose A/B/C/D, and then render/run. The highest-priority expansion is secure heap state lifecycle, followed by cipher/AEAD lifecycle, ASN.1 nested boundary, and PKEY verify semantic families.

## Commit Guidance

Commit reports, compact JSON/YAML summaries, pattern bank updates, raw pattern docs, scheduler outputs, and feedback. Avoid or split bulky logs, build binaries, cache files, and repeated generated case payloads.

## Recommendation

Temporarily pause new PoC execution long enough to commit the framework milestone and unify renderer/analyzer interfaces. Then resume discovery through pattern expansion.
