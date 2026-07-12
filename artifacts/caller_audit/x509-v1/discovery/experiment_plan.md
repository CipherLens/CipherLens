# MLS++ X509 exact-single-certificate experiment plan

## Scope and guardrails

This plan is limited to the already selected local static caller candidate:

- Repository: `cisco/mlspp`
- Fixed commit: `92aaa4134fa45ec39957a7c81a342401fba7feb2`
- Callsite: `lib/hpke/src/certificate.cpp:96`
- Function: `Certificate::ParsedCertificate::parse(const bytes& der)`
- Parser: `d2i_X509`
- Static classification: `exact_single_certificate_candidate`

A future implementation must use only locally generated self-signed test certificates and synthetic byte buffers. It must not use DNS, TLS connections, MLS services, mail systems, or any other external service. The original MLS++ checkout must remain unchanged. All experimental source changes, including the fix-control, must be made in independent worktrees rooted at the fixed commit.

This document is a plan only. No harness is implemented, no build is run, and no runtime behavior is claimed here.

## Fixture design

Generate all keys and certificates locally in a temporary directory. Do not commit private keys, generated certificates, binaries, build directories, or large logs.

The fixture set must contain:

1. An active self-signed root certificate with an explicit serial number.
2. An active leaf certificate signed by that root, with a different explicit serial number.
3. A different active certificate with a different key, subject, issuer relationship, and serial number.
4. A second root certificate used only to form a leaf/root chain whose leaf signature does not validate under the supplied root.
5. An expired certificate.
6. A not-yet-valid certificate.

For every generated certificate, record its canonical DER length, SHA-256 file digest, subject, issuer, certificate serial number, public-key digest, and validity interval in a small run-local manifest. The manifest may be retained as a compact result artifact, but private keys must remain temporary.

The Certificate public API exposes `subject()` and `issuer()` but does not expose the X.509 certificate serial number. The future harness must therefore obtain the certificate serial through a separate read-only OpenSSL observation helper using `X509_get_serialNumber`, or through narrowly scoped test-only instrumentation in the experimental worktree. It must not treat the subject distinguished-name `serialNumber` attribute as the certificate serial number.

## Corpus

For each canonical DER certificate `C`, construct the following bounded byte vectors:

| Case | Bytes |
| --- | --- |
| `canonical` | `C` |
| `tail_0500` | `C || 05 00` |
| `tail_3000` | `C || 30 00` |
| `tail_020100` | `C || 02 01 00` |

The baseline positive control is mandatory: the canonical DER certificate must parse successfully through the selected `Certificate(const bytes&)` path. If it does not, stop the experiment and classify the result as `caller_behavior_not_confirmed`.

The three mutations are observations, not assumed outcomes. Record whether each is accepted and, when accepted, run every applicable Certificate-level and credential-level oracle below.

## Baseline positive control

For the active canonical leaf and root certificates:

1. Construct `Certificate` from canonical DER.
2. Require successful parsing.
3. Record `Certificate::raw`, `Certificate::hash()`, `subject()`, `issuer()`, the observed certificate serial, serialized public key, and `expiration_status()`.
4. Construct a one-certificate `X509Credential`.
5. Construct a two-certificate `X509Credential` ordered as leaf then root.
6. Require the correctly signed leaf/root pair to pass the constructor's adjacent-certificate signature validation.
7. Record the extracted `SignaturePublicKey`, credential equality baseline, and TLS serialization bytes.

A failure in any mandatory canonical setup step invalidates comparisons that depend on that step and yields `caller_behavior_not_confirmed`.

## Certificate-level oracle

For canonical and each accepted tail mutation, emit one structured row with at least:

- `case`
- `accepted`
- `exception_class`
- `reason`
- `input_length`
- `consumed_length`, from a separate direct OpenSSL observer
- `raw_sha256`
- `raw_differs_from_canonical`
- `certificate_equal_to_canonical`
- `certificate_hash`
- `certificate_hash_equal`
- `subject`
- `subject_equal`
- `issuer`
- `issuer_equal`
- `certificate_serial`
- `certificate_serial_equal`
- `public_key_sha256`
- `public_key_equal`
- `expiration_status`
- `expiration_status_equal`

The comparisons must exercise the actual public MLS++ behavior where available:

- Raw representation: compare `Certificate::raw`.
- Certificate equality: invoke `Certificate::operator==`.
- Certificate digest: compare `Certificate::hash()`, which is derived from `X509_digest`.
- Subject and issuer: compare the parsed maps returned by `subject()` and `issuer()`.
- Public key: serialize or otherwise normalize `Certificate::public_key` using the selected signature algorithm, then compare bytes and SHA-256.
- Expiration: compare `expiration_status()` under the same captured wall-clock instant.
- Certificate serial: use the separate observation method described in Fixture design and label it as supplementary because it is not exposed by the public Certificate API.

The harness must distinguish raw-representation equality from parsed-certificate equality. A raw difference alone is not evidence that subject, issuer, serial, public key, digest, or validity semantics changed.

## X509Credential-level oracle

### One-certificate credential

For canonical and each tail mutation:

1. Construct `X509Credential` from a vector containing exactly one DER byte vector.
2. Record success or exception.
3. Record the extracted `SignaturePublicKey`.
4. Compare it with the canonical credential's extracted key.
5. Compare the canonical and mutated credentials with `X509Credential::operator==`.
6. Serialize each credential through the MLS TLS serializer.
7. Deserialize it again locally.
8. Verify whether the serialized and round-tripped `CertData.data` preserves the exact trailing bytes.
9. Repeat the extracted-key and equality observations after the round trip.

### Two-certificate leaf/root chain

Exercise at least these variants:

| Variant | Leaf element | Root element |
| --- | --- | --- |
| `chain_canonical` | canonical | canonical |
| `chain_tail_leaf_0500` | tail_0500 | canonical |
| `chain_tail_leaf_3000` | tail_3000 | canonical |
| `chain_tail_leaf_020100` | tail_020100 | canonical |
| `chain_tail_root_0500` | canonical | tail_0500 |
| `chain_tail_root_3000` | canonical | tail_3000 |
| `chain_tail_root_020100` | canonical | tail_020100 |

For every accepted variant, record:

- Whether construction of the two-element `X509Credential` succeeds.
- Whether the adjacent leaf/root signature validation remains successful.
- A direct `leaf.valid_from(root)` result using the corresponding `Certificate` objects.
- Whether the extracted leaf `SignaturePublicKey` equals the canonical chain's key.
- Whether `X509Credential::operator==` changes when only a raw DER representation changes.
- Whether TLS serialization preserves the exact mutated element, including trailing bytes.
- Whether deserializing that TLS representation reconstructs the same raw credential representation.
- Whether `Credential::valid_for` produces the same result when given the canonical leaf public key.

The chain oracle must describe MLS++ accurately: the constructor performs adjacent certificate signature checks with `X509_verify`; it is not a full trust-store validation with `X509_verify_cert`. The plan must not infer trust-anchor or deployment policy behavior from this local chain check.

## Negative controls

### Invalid DER

Use a short malformed DER buffer that cannot represent an X.509 certificate.

Expected control behavior:

- `Certificate` construction rejects it.
- A one-certificate `X509Credential` rejects it.
- Baseline and fix-control results remain equivalent.

### Different certificate

Use the separately generated active certificate with different key, subject, issuer relationship, and serial number.

Expected observations:

- Standalone parsing may succeed.
- Raw bytes, `Certificate::operator==`, certificate hash, subject or issuer, serial, and public key must expose the expected differences.
- Extracted `SignaturePublicKey` must differ from the canonical leaf key.
- This control demonstrates that the equality and key oracles can detect a genuinely different certificate.

### Incorrectly signed leaf/root chain

Pair a leaf signed by the first root with the unrelated second root.

Expected control behavior:

- Standalone leaf and root parsing may succeed.
- `leaf.valid_from(wrong_root)` returns false.
- Two-element `X509Credential` construction rejects the chain with certificate-chain validation failure.
- Baseline and fix-control behavior remain equivalent.

### Expired and not-yet-valid certificates

Parse the expired and not-yet-valid fixtures and record `expiration_status()`.

These are semantic controls, not assumed parser failures. The inspected `X509Credential` constructor validates adjacent signatures but does not itself call `expiration_status()` or `X509_verify_cert`. Therefore the experiment must record whether credential construction succeeds and must not treat success as an unexpected result. The required oracle is that the public expiration status distinguishes expired, inactive, and active fixtures consistently before and after the fix-control.

## Fix-control

Create a separate MLS++ worktree at `92aaa4134fa45ec39957a7c81a342401fba7feb2`. Do not modify the original checkout.

In that worktree only, add a full-consumption check immediately after successful `d2i_X509` parsing in `Certificate::ParsedCertificate::parse`:

1. Preserve the input start pointer.
2. Parse with the existing length.
3. Preserve the existing null-result error behavior.
4. Require `buf == der.data() + der.size()`.
5. Reject successful prefix parses when the pointers differ.
6. Use a deterministic exception class and reason that the result collector can distinguish from invalid DER.

Run the same corpus and oracles against baseline and fix-control.

Required fix-control assertions:

- Canonical DER remains accepted.
- `tail_0500`, `tail_3000`, and `tail_020100` are all rejected.
- Invalid DER remains rejected.
- The different certificate remains accepted as a distinct valid certificate.
- The incorrectly signed leaf/root chain remains rejected for the same chain-validation reason.
- Expired and not-yet-valid certificate parsing and expiration-status observations remain unchanged.
- No result row may silently omit an oracle solely because the implementation changed; rejected tail rows must explicitly mark downstream fields as not reached.

A future implementation should use the fixed OpenSSL version selected for the broader caller-audit work and enable ASan and UBSan. Those actions are not performed in this discovery phase.

## Result classification

The result collector may emit only the following classification values:

- `caller_behavior_not_confirmed`
- `representation_differential_confirmed`
- `credential_identity_differential_confirmed`
- `security_impact_unproven`

Apply them as follows:

1. Use `caller_behavior_not_confirmed` if the mandatory canonical caller path cannot be reproduced, or if the assumed baseline tail behavior is not observed.
2. Use `representation_differential_confirmed` when accepted inputs parse to the same certificate semantics but differ in retained raw bytes, `Certificate::operator==`, or TLS serialization.
3. Use `credential_identity_differential_confirmed` only when the representation difference propagates to a credential-level identity observable, such as `X509Credential::operator==`, `Credential::valid_for`, extracted `SignaturePublicKey`, or a chain-validation result. The report must name the exact changed observable.
4. Include `security_impact_unproven` whenever no real MLS state, cache, deduplication, credential-binding, or policy consequence has been demonstrated. This remains required even if a representation or credential-identity differential is confirmed.

Classifications may be emitted as an ordered list when more than one statement is simultaneously supported. No unlisted classification value may be introduced.

## Interpretation boundary

Even if raw-byte, equality, or TLS-serialization differences are confirmed, they must not automatically be described as a vulnerability. Security-impact validation may begin only if evidence shows that a real MLS state transition, cache, deduplication decision, credential binding, or policy decision changes in a way that an actor cannot obtain with the canonical certificate.

This experiment alone is designed to establish caller and representation behavior. It does not establish a deployment consequence.
