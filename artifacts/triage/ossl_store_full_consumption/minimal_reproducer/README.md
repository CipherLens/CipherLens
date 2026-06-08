# Minimal Reproducer: OpenSSL App-Level DER Trailing Data Acceptance

## Status

This is a semantic issue candidate, not a crash and not a confirmed CVE.

The observed behavior is:

- a clean DER object is accepted;
- the same DER object followed by malformed ASN.1 trailing bytes is also accepted;
- the malformed ASN.1 bytes alone are rejected.

Classification:

```text
app_level_accepts_valid_prefix_with_malformed_tail
```

## Environment

OpenSSL command used:

```text
/home/wen/work/clean_sources/openssl-3.5.5/apps/openssl
```

Version output is recorded in:

```text
results/openssl_version.txt
```

Observed version:

```text
OpenSSL 3.5.5 27 Jan 2026
```

## Inputs

Input root:

```text
artifacts/triage/ossl_store_full_consumption/minimal_reproducer/inputs
```

For each object family, three inputs are provided:

```text
baseline_valid.der
valid_plus_malformed_tail.der
malformed_only.der
```

The malformed tail is:

```text
30 82 10 00
```

Tail proof is recorded in:

```text
results/input_tail_hex.txt
```

### X509

```text
inputs/x509_der/baseline_valid.der
inputs/x509_der/valid_plus_malformed_tail.der
inputs/x509_der/malformed_only.der
```

Lengths:

```text
baseline_len=687
malformed_tail_len=691
malformed_only_len=4
```

### PKCS#8 / Private Key

```text
inputs/pkcs8_der/baseline_valid.der
inputs/pkcs8_der/valid_plus_malformed_tail.der
inputs/pkcs8_der/malformed_only.der
```

Lengths:

```text
baseline_len=1218
malformed_tail_len=1222
malformed_only_len=4
```

### Public Key

```text
inputs/pubkey_der/baseline_valid.der
inputs/pubkey_der/valid_plus_malformed_tail.der
inputs/pubkey_der/malformed_only.der
```

Lengths:

```text
baseline_len=294
malformed_tail_len=298
malformed_only_len=4
```

## Minimal Commands

Set:

```bash
OPENSSL=/home/wen/work/clean_sources/openssl-3.5.5/apps/openssl
ROOT=artifacts/triage/ossl_store_full_consumption/minimal_reproducer
```

### X509 fingerprint

```bash
$OPENSSL x509 -inform DER -in "$ROOT/inputs/x509_der/baseline_valid.der" -fingerprint -noout
$OPENSSL x509 -inform DER -in "$ROOT/inputs/x509_der/valid_plus_malformed_tail.der" -fingerprint -noout
$OPENSSL x509 -inform DER -in "$ROOT/inputs/x509_der/malformed_only.der" -fingerprint -noout
```

Observed:

```text
baseline_valid.der: exit 0, fingerprint printed
valid_plus_malformed_tail.der: exit 0, fingerprint printed
malformed_only.der: exit 1, stderr error
```

### X509 export

```bash
$OPENSSL x509 -inform DER -in "$ROOT/inputs/x509_der/valid_plus_malformed_tail.der" -outform PEM -out "$ROOT/outputs/x509_tail.pem"
```

Observed:

```text
exit 0, PEM output file created and non-empty
```

### Private key public-key extraction

```bash
$OPENSSL pkey -inform DER -in "$ROOT/inputs/pkcs8_der/valid_plus_malformed_tail.der" -pubout -out "$ROOT/outputs/pkey_tail_pub.pem"
```

Observed:

```text
exit 0, public-key PEM output file created and non-empty
```

### PKCS#8 conversion

```bash
$OPENSSL pkcs8 -inform DER -in "$ROOT/inputs/pkcs8_der/valid_plus_malformed_tail.der" -nocrypt -outform PEM -out "$ROOT/outputs/pkcs8_tail.pem"
```

Observed:

```text
exit 0, converted PEM output file created and non-empty
```

### Public key re-export

```bash
$OPENSSL pkey -pubin -inform DER -in "$ROOT/inputs/pubkey_der/valid_plus_malformed_tail.der" -pubout -out "$ROOT/outputs/pubkey_tail.pem"
```

Observed:

```text
exit 0, public-key PEM output file created and non-empty
```

## Full Command Matrix

Detailed results:

```text
results/minimal_command_matrix.csv
results/minimal_command_summary.json
logs/*.stdout.txt
logs/*.stderr.txt
```

Summary:

```text
total_commands=15
baseline_success=5/5
valid_plus_malformed_tail_accepted=5/5
malformed_only_rejected=5/5
```

No command in this minimal reproducer produced a crash or sanitizer signal.

## Risk Boundary

This should not be reported as memory corruption.
It should not be described as a confirmed CVE without an affected security workflow.

The lower-level `d2i_*` behavior can be interpreted as API design: successful decoding advances the input pointer and leaves full-consumption checks to the caller.
`OSSL_STORE` also has object-stream semantics.

The stronger observation is at the application layer:

- `openssl x509` can fingerprint/export a leading certificate while ignoring malformed trailing ASN.1 bytes.
- `openssl pkey` can extract a public key from a leading private key while ignoring malformed trailing ASN.1 bytes.
- `openssl pkcs8` can convert a leading private key while ignoring malformed trailing ASN.1 bytes.
- `openssl pkey -pubin` can re-export a leading public key while ignoring malformed trailing ASN.1 bytes.

This may be an app-level full-consumption validation gap if these commands are intended to validate a single DER object file.

## Question For Upstream

```text
Do OpenSSL app commands such as x509/pkey/pkcs8 intend to accept DER files that contain a valid leading object followed by malformed ASN.1 trailing bytes? Should these commands enforce full input consumption in single-object DER mode, or should the current behavior be documented?
```

## Reproduction Script

The local helper script used to generate this minimal package is:

```text
run_minimal_reproducer.py
```

It copies the representative inputs from the larger corpus, creates the 4-byte malformed-only controls, executes the command matrix, and writes the result CSV/JSON/log files.
