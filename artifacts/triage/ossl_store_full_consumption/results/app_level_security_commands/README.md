# App-Level Malformed Tail Command Validation

## Inputs

Input root:

- `artifacts/triage/ossl_store_full_consumption/inputs/`

Object families:

- `x509_der`
- `pkcs8_der`
- `pubkey_der`

Mutations:

- `baseline_empty`
- `malformed_partial_sequence`
- `malformed_oversized_len`
- `malformed_indefinite_len`
- `truncated_integer`
- `truncated_bit_string`
- `bad_asn1_tag`
- `valid_null_then_malformed_seq`

## Outputs

- `command_matrix.csv`
- `command_summary.json`

## Command matrix summary

Total command cases: 120

- Baseline cases: 15
- Malformed-tail cases: 105
- Accepted total: 120
- Accepted malformed-tail cases: 105
- Accepted with warning: 6
- Rejected: 0

The only warning cases were `storeutl` cases where trailing data produced an unsupported-object diagnostic on stderr while the command still exited 0.

## App-level scenarios

All malformed-tail scenarios below were accepted:

- `openssl x509 -inform DER -in <file> -noout`
- `openssl x509 -inform DER -in <file> -fingerprint -noout`
- `openssl x509 -inform DER -in <file> -outform PEM -out <out.pem>`
- `openssl pkey -inform DER -in <file> -pubout -out <pubout.pem>`
- `openssl pkcs8 -inform DER -in <file> -nocrypt -outform PEM -out <converted.pem>`
- `openssl pkey -pubin -inform DER -in <file> -pubout -out <pubkey_out.pem>`

Interpretation:

- `x509 -noout` succeeds as a format/check command on malformed-tail DER.
- `x509 -fingerprint` computes a fingerprint from the leading certificate.
- `pkey -pubout` exports a public key from a malformed-tail private key file.
- `pkcs8 -nocrypt -outform PEM` converts a malformed-tail private key file.
- `pkey -pubin -pubout` re-exports a malformed-tail public key file.

## Proposed analyzer result levels

### `low_level_d2i_prefix_parse`

Low-value candidate.
This is expected low-level API behavior when the caller does not compare the advanced DER pointer with the input end.

### `caller_pattern_accepts_trailing_garbage`

Medium-value candidate.
A local caller pattern accepts a valid leading DER object and ignores trailing bytes.
Value depends on whether the caller is security-relevant or only a harness/helper.

### `ossl_store_accepts_malformed_tail`

Medium-value candidate.
OSSL_STORE loads a leading supported object and can expose EOF/error state only if the caller continues reading.
This is useful evidence but still partly API-design behavior.

### `app_command_accepts_malformed_tail`

High-value candidate.
An OpenSSL command that users may treat as object validation, extraction, or conversion exits 0 on malformed-tail DER.
This is the strongest current category for x509/pkey/pkcs8 command behavior.

### `app_command_accepts_with_warning`

Triage candidate.
The command exits 0 and emits diagnostics on stderr.
For `storeutl`, this is weaker because the command is an object-stream inspection tool and did not silently accept all trailing data.

### `documented_allowed_behavior`

Not a vulnerability candidate by itself.
Use this when docs clearly specify prefix parsing, multi-object streaming, or caller-managed full-consumption checks.

### `ambiguous_semantic_candidate`

Triage candidate.
Use this when docs do not clearly promise full consumption, but command behavior may violate user expectations for a validation or conversion command.

## Upstream issue framing

Suggested framing:

- Treat as an app-level DER validation gap candidate.
- Emphasize that x509/pkey/pkcs8 can extract, fingerprint, or convert the leading object while ignoring malformed trailing ASN.1 data.
- Distinguish this from low-level `d2i_*` prefix parsing and from `storeutl` multi-object STORE semantics.
- Avoid claiming memory corruption or CVE-level impact without a demonstrated security boundary bypass in a real workflow.
