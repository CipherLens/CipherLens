# DER Full-Consumption Verdict Taxonomy

This note defines result labels for DER full-consumption and malformed-tail
triage. It is intended to separate low-level parser behavior from app-level
validation behavior.

## Scope

The motivating evidence is the OpenSSL app-level DER malformed-tail candidate:

```text
valid DER object || malformed ASN.1 tail
```

with the malformed tail:

```text
30 82 10 00
```

The observed app-level pattern is:

```text
baseline valid DER: accepted
valid DER prefix + malformed tail: accepted
malformed-only tail: rejected
```

This is a semantic validation-gap candidate, not a crash and not a confirmed
CVE.

## Verdicts

### `low_level_d2i_prefix_parse`

Low-value candidate.

Use when a low-level `d2i_*` API parses a valid DER prefix and leaves trailing
bytes observable through the advanced input pointer.

Reasoning:

- `d2i_*` APIs expose pointer consumption to the caller.
- Full input consumption is caller-enforced, not automatically guaranteed.
- This result should not be reported as a vulnerability without caller context.

### `caller_pattern_accepts_trailing_garbage`

Medium-value candidate.

Use when a caller invokes a DER parser or STORE-like API and accepts a valid
leading object without checking whether all input was consumed.

Reasoning:

- This is stronger than raw `d2i_*` behavior.
- It still needs caller purpose analysis before being considered security-relevant.

### `ossl_store_accepts_malformed_tail`

Medium to high-value candidate.

Use when `OSSL_STORE_load()` returns a valid leading object while malformed
trailing bytes remain in the stream.

Reasoning:

- OSSL_STORE has object-stream semantics.
- The behavior may be documented or intended for multi-object stores.
- It becomes more important when a single-object app helper stops after the
  first matching object.

### `app_command_accepts_malformed_tail`

High-value candidate.

Use when an app command exits successfully for an input containing a valid
leading object plus malformed trailing bytes.

Examples:

- `openssl x509 -inform DER`
- `openssl pkey -inform DER`
- `openssl pkcs8 -inform DER`
- `openssl req -inform DER`
- `openssl crl -inform DER`

### `app_command_accepts_with_warning`

Triage candidate.

Use when an app command exits successfully but emits diagnostics on stderr.

Reasoning:

- This is weaker than silent acceptance.
- It may be acceptable for object-stream inspection tools such as `storeutl`.

### `app_level_accepts_valid_prefix_with_malformed_tail`

High-value candidate.

Use when all of the following hold:

```text
baseline valid DER: accepted
valid DER prefix + malformed tail: accepted
malformed-only tail: rejected
```

This distinguishes a real valid-prefix acceptance pattern from malformed input
being accidentally accepted in general.

### `real_app_level_validation_gap_candidate`

Highest-confidence semantic candidate in this taxonomy.

Use when:

- multiple user-facing commands accept valid-prefix malformed-tail inputs;
- those commands can fingerprint, export, display, or convert the leading
  object;
- malformed-only controls are rejected;
- no crash or sanitizer signal is required for the claim.

This label still does not mean confirmed vulnerability or CVE. It means the
candidate is ready for upstream semantic clarification.

### `documented_allowed_behavior`

Not a vulnerability candidate.

Use when documentation clearly says that prefix parsing, multiple objects, or
caller-managed full-consumption checks are expected behavior.

### `ambiguous_semantic_candidate`

Needs triage.

Use when the behavior may surprise users, but documentation and security impact
are not yet clear enough to assign a stronger label.

## App-Level Boundary

Low-level API behavior and app-level behavior should be reported separately:

```text
d2i_* prefix parse
    -> low_level_d2i_prefix_parse

OSSL_STORE loads first valid object from a stream
    -> ossl_store_accepts_malformed_tail

single-object helper stops after first requested object
    -> caller_pattern_accepts_trailing_garbage

user-facing app command fingerprints/exports/converts valid prefix
    -> app_level_accepts_valid_prefix_with_malformed_tail
    -> real_app_level_validation_gap_candidate, if repeated across commands
```

## Reporting Guidance

Recommended wording:

```text
This is an app-level DER full-consumption validation gap candidate. It is not a
crash and not a confirmed CVE. The question for upstream is whether single-object
DER modes in app commands should reject malformed trailing ASN.1 bytes or
document that trailing data may be ignored.
```

Avoid:

```text
confirmed vulnerability
memory corruption
arbitrary malformed DER accepted
```

unless additional evidence supports those claims.
