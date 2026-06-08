# Semantic Candidate Verdict Taxonomy

This taxonomy generalizes the DER full-consumption labels into a broader set of
semantic discovery classes. It separates low-level API behavior, caller-pattern
behavior, app-level validation gaps, and issue-grade candidates.

## DER Full-Consumption Layers

`low_level_d2i_prefix_parse`
: Low-value candidate. A low-level `d2i_*` API parses a valid DER prefix and
  advances the input pointer only to the consumed object. Whole-input validation
  is the caller's responsibility, so this is not issue-grade without caller
  context.

`caller_pattern_accepts_trailing_garbage`
: Medium-value candidate. A caller accepts a parsed object without checking
  complete input consumption.

`ossl_store_accepts_malformed_tail`
: Medium to high-value candidate. `OSSL_STORE_load()` returns a valid leading
  object while malformed bytes remain. This needs interpretation because
  OSSL_STORE can model object streams.

`app_command_accepts_malformed_tail`
: High-value candidate. A real OpenSSL app command exits successfully for
  `valid DER || malformed ASN.1 tail`.

`app_command_accepts_with_warning`
: High-value candidate when the command still produces useful object output.
  The warning must be recorded; it may reduce severity but does not erase the
  app-level acceptance behavior.

`app_level_accepts_valid_prefix_with_malformed_tail`
: High-value behavior signature. The app accepts `valid object || malformed
  tail` while rejecting the malformed-only tail.

`real_app_level_validation_gap_candidate`
: Issue-grade candidate. The app-level command/helper accepts valid-prefix
  malformed-tail input, rejects malformed-only input, and produces useful output
  such as fingerprint, export, conversion, parsed text, or a public key.

`documented_allowed_behavior`
: API design behavior. Use only when documentation or source-level intent says
  prefix parsing or stream parsing is allowed for that specific caller.

`ambiguous_semantic_candidate`
: Needs manual review. The behavior is unusual but lacks enough oracle,
  documentation, or caller-context evidence.

## General Classes

`unexpected_success_candidate`
: Mutated invalid input succeeds where the oracle expects rejection or safe
  error behavior. High value when the API output is security-relevant.

`failure_path_output_state_triage`
: A return-code or failure-path case where output length, output buffer, or
  object state may be polluted after failure.

`allowed_legacy_semantics`
: A behavior difference caused by documented compatibility semantics rather
  than a validation gap.

`projection_limitation`
: The migrated harness does not preserve the original vulnerability path well
  enough to classify the result as a candidate.

`safe_negative`
: The mutation is rejected or handled safely. Safe/safe results are valid
  experimental outcomes and must not be reported as vulnerabilities.

`harness_error`
: Compile, link, render, adapter, or setup error. These can enter a repair
  queue, but they are not vulnerability candidates.

## Value Guidance

Low-value candidates:

- `low_level_d2i_prefix_parse`
- `documented_allowed_behavior`
- `safe_negative`
- `projection_limitation`
- `harness_error`

High-value candidates:

- `unexpected_success_candidate`
- `failure_path_output_state_triage`
- `app_command_accepts_malformed_tail`
- `app_level_accepts_valid_prefix_with_malformed_tail`
- `real_app_level_validation_gap_candidate`

Issue-grade candidates:

- Must be reachable through a real app/helper or security-relevant caller.
- Must show a clear malformed-input contrast, such as baseline accepted,
  mutated-prefix accepted, malformed-only rejected.
- Must produce meaningful output or state transition.
- Must include exact command, exit code, stdout/stderr, and source-level call
  path evidence.

API design behavior:

- Low-level prefix parsing can be allowed when callers are expected to inspect
  consumed pointers.
- Object-stream APIs can accept multiple objects when the caller drains the
  stream or intentionally takes one object.

Crash handling:

- Do not treat every nonzero harness exit as a crash.
- Require ASan, UBSan, SEGV, exit code 139, `heap-buffer-overflow`,
  `stack-buffer-overflow`, `use-after-free`, or equivalent evidence.
- A nonzero exit can be an intentional oracle signal such as `[BUG] target
  decoded first DER object but left trailing garbage unconsumed.`

