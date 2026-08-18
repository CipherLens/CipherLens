# Current Pipeline v2

## Canonical Contract and Transfer Foundation

The canonical v2 method begins by separating historical validation semantics
from target migration eligibility:

```text
validated Vulnerability Contract v0.3
  -> Transfer Signature v0.1
  -> target semantic facts
  -> deterministic eligibility
```

The Vulnerability Contract defines what must be validated. Transfer Signature
is the Contract-derived Target Eligibility Specification: it defines the typed
capabilities, excluded semantics, and observability obligations that a target
semantic surface must satisfy before migration. The implementation now also
contains the isolated Batch 3B foundations:

```text
legacy/current Trigger Template
  -> stable Trigger Template Interface Manifest

provider payload (advisory only)
  -> trusted BindingProposal envelope (PROPOSED only)

ELIGIBLE evaluation + explicit verified mapping
  -> immutable CandidateBinding v0.1
  -> ten deterministic checks
  -> VALID / INVALID / INCOMPLETE
```

The Batch 4B foundation now implements the formal Contract-guided Matcher
orchestration from deterministic RecallQuery and multi-subject candidate
assembly through proposal, fact resolution, TS hard filtering, concrete
observability, post-gate ranking, and canonical CandidateBinding validation.
The Batch 5B foundation now consumes only a VALID CandidateBinding and
deterministically projects the complete binding into a canonical
Template–CandidateBinding Merge, separate Bound Template Source, and canonical
SourceMap. Declared syntax/glue holes may be resolved only by exact allowlisted
Programmatic Completion or a PROPOSED constrained adaptation followed by
trusted rerendering and all 18 deterministic validation checks. Semantic or
protected-source drift routes to whole-binding switching; components are never
mixed across CandidateBindings.

The current v2 foundation still does not implement compile/link/run,
Structured Execution Trace, Contract verdict, or UNKNOWN evidence rerun.
Provider output cannot directly establish VERIFIED facts, eligibility,
CandidateBinding validity, trusted source, execution truth, or vulnerability
truth. The detailed boundaries are specified in
`docs/binding_proposal_v0_1.md`,
`docs/llm_role_proposal_provider_v0_1.md`, and
`docs/candidate_binding_v0_1.md`; Matcher-specific orchestration is specified in
`docs/matcher_v0_1.md`, and Merge/source/adaptation semantics are specified in
`docs/template_binding_merge_v0_1.md`.

The scheduler, A/B/C/D paths, RAG metadata, API cards, adapter recipes, and
candidate scores described below are legacy implementation components and
evidence sources. They do not define Transfer Signature truth and cannot decide
eligibility. The canonical TS semantics and boundary are specified in
`docs/transfer_signature_v0_1.md`.

## Old Linear Chain

The earlier mainline was:

```text
single PoC
  -> AST-lite mask
  -> RAG API mapping
  -> LLM slot filling
  -> adapter_validate
  -> cross harness
  -> analyze
```

That chain is still valid for API-level recipe-slot migration.

## New Scheduler-Oriented Chain

The current integration chain is:

```text
Pattern Bank
  -> RAG
  -> Candidate Queue
  -> Scheduler
  -> Execution Path Planner
  -> A/B/C/D execution paths
  -> feedback loop
```

The new framework does not cancel AST-lite masking, selected mask units, or LLM slot filling. It changes their scope. They are no longer mandatory global steps for every family. They are local required steps of path A.

## Execution Paths

### A. Recipe-Slot Cross-Library Migration

Path A is for API-level cross-library semantic migration. It keeps the original research spine:

- normalized source template
- `mask_report.yaml`
- AST-lite multi-granularity masking
- `selected_mask_units.yaml`
- RAG-backed API mapping
- LLM-filled `slot_bindings`
- structured `adapter.yaml`
- `adapter_validate`
- controlled cross-template generation
- template-based rendering and oracle-based analysis

The LLM must not generate free-form C harnesses in this path.

### B. Controlled Family Mutation Sprint

Path B is for families with known mutation dimensions and controlled renderers. It can use render matrices and feedback scoring without requiring a source PoC AST for every case. PKEY v1 and DER full-consumption v2 are examples of this style.

### C. App-Level Validation Gap Triage

Path C is for real CLI/app command behavior. The oracle is app exit status, stderr, output artifact existence/content, and input controls. DER v2 does not use AST masking in this path because it tests OpenSSL app behavior around valid DER prefixes plus malformed trailing bytes, not direct cross-library API adapter generation.

### D. Crash/Sanitizer Evidence Audit

Path D is for crash or sanitizer candidates. It verifies crash logs, sanitizer signatures, versions, and harness validity before promoting a candidate into a runnable family. A nonzero harness exit code alone is not enough.

The current top5 crash/sanitizer audit is complete. It found one ready sprint seed, `OPENSSL-ISSUE-28669`, for a proposed `secure_heap_state_lifecycle_v1` family because the local artifact records SIGSEGV, exit code 139, and Valgrind Invalid read evidence. This is a sprint recommendation, not a new vulnerability claim. The other audited top5 entries still need manual confirmation of original inputs, affected versions, sanitizer logs, or harness validity.

## DER v2 Position

DER full-consumption v2 is currently an app-level validation-gap candidate. The useful result is not a crash and not a confirmed CVE. It shows that controlled mutation plus app-runner analysis can systematize evidence already seen in OSSL_STORE/app-level triage.

The C path status is complete for the current DER app-level validation-gap triage. Its result should remain framed as app-level semantic validation evidence, not a crash/sanitizer finding.

## MAC Lifecycle Position

MAC lifecycle has now completed the GLM-assisted full A-path:

```text
GLM slot filling -> adapter_validate -> cross_generator_from_adapters -> render_cases -> compile_run -> generic analyze_results/analyze_cross_results
```

The compliance status is `full_a_path_compliant`. The standard run lives under `artifacts/migrations/mac_lifecycle_glm_full_a_path/` and records 8 runnable cases, 4 OpenSSL/mbedTLS pairs, 2 `migrated_safe` pairs, and 2 `migration_needs_triage` pairs. The triage pairs are OpenSSL repeated-final and update-after-final permissive behavior relative to mbedTLS PSA bad-state rejection. This is semantic divergence evidence, not a confirmed vulnerability.

This update does not change the DER / D-path conclusions. The next planned sprint can continue to `secure_heap_state_lifecycle_v1` with MAC A-path status recorded.

## Secure Heap Lifecycle Position

`secure_heap_state_lifecycle_v1` is now classified as D-then-B seed validation
and oracle calibration for `OPENSSL-ISSUE-28669`. It is not a cross-library
migration result and should not be treated as the final discovery output.

Version provenance confirms that the current runnable sprint uses local
`openssl-3.5.5` from `${CLEAN_SOURCES_ROOT}` via static `libcrypto.a` linkage.
The historical artifact only records local validation against OpenSSL 3.0.13;
original affected versions, fixed version, and patch commit are not available in
local artifacts.

The current novelty label is:

```text
current_version_robustness_candidate_with_unknown_historical_overlap
```

The next stage is pattern expansion:

- OpenSSL same-family secure-heap API/state expansion.
- OpenSSL cross-version core matrix.
- Cross-library analogous lifecycle oracle, without forcing
  `CRYPTO_secure_used` into an mbedTLS equivalent.
