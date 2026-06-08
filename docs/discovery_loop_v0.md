# Discovery Loop v0

This document defines a small discovery feedback loop for the crypto
vulnerability-pattern migration framework. The goal is to turn interesting
runner and app-level observations into structured triage, constrained repair,
and family-level mutation refinement.

## 1. Current Chain

```text
PoC / issue
-> normalized template
-> AST mask / selected units
-> candidate API evidence
-> RAG / API knowledge
-> LLM recipe-slot filling
-> cross template
-> render cases
-> compile/run
-> analyze
```

This chain is still the main migration workflow. It keeps the LLM constrained
to structured adapter or slot binding output, and leaves final harness rendering
to deterministic templates.

## 2. Discovery Feedback Loop

```text
analyze results
-> behavior novelty clustering
-> candidate triage queue
-> repair queue
-> constrained LLM repair
-> rerender / rerun
-> family-level mutation refinement
```

The loop adds two lightweight control points:

- `behavior novelty clustering`: find crash signals, semantic candidates,
  unexpected success, app-level validation gaps, safe negatives, and projection
  limitations across existing result files.
- `repair queue`: generate bounded repair tasks only for harness construction
  failures, not for genuine crashes or semantic candidates.

## 3. Result Classes

`crash_candidate`
: ASan, UBSan, SEGV, exit code 139, or comparable sanitizer-backed evidence.
  A nonzero harness exit alone is not enough.

`unexpected_success_candidate`
: A mutated invalid input succeeds where the oracle expects rejection or safe
  error handling.

`real_app_level_validation_gap_candidate`
: A real command/helper accepts `valid object || malformed tail`, rejects the
  malformed-only input, and produces useful app-level output such as fingerprint,
  export, conversion, or parsed text.

`semantic_candidate`
: A target behavior matches a migrated semantic oracle but needs caller or API
  design interpretation before issue escalation.

`behavior_divergence_candidate`
: Source and target differ in a way that is observable but not yet mapped to a
  precise oracle.

`safe_negative`
: The source and target both reject or handle the mutation safely.

`projection_limitation`
: The harness reaches a related API but does not preserve the original
  vulnerability path strongly enough for a candidate claim.

`harness_error`
: The harness itself fails due to compile, link, render, setup, or malformed
  adapter issues.

`discarded_after_3_repairs`
: A harness error remains after three constrained repair attempts.

## 4. LLM Repair Boundaries

Allowed repair scope:

```text
include missing
function signature error
type mismatch
variable binding error
buffer length constant missing
OpenSSL / mbedTLS API parameter order error
slot binding error
```

Forbidden repair scope:

```text
remove oracle
remove sanitizer
skip trigger call
change candidate to safe
change mutation semantics
delete failure path
```

Repair prompts must preserve the oracle, sanitizer configuration, trigger call,
mutation payload, and expected verdict. If the same case still fails after
three attempts, it should be marked `discarded_after_3_repairs` instead of being
silently weakened.

## 5. Family-Level Feedback

High-value findings should update family-level knowledge, not one-off code.
Examples:

- DER full-consumption findings update DER parser cards, caller-pattern
  taxonomy, and mutation hints.
- PKEY verify/sign findings update state preconditions and object-type
  dispatch hints.
- MAC lifecycle findings update setup/final/abort sequence hints.
- Bignum/buffer findings update caller-buffer and explicit-length observables.

