# MBEDTLS-POC-0020: RSA DER trailing garbage migration experiment

## Overview

This experiment reproduces and migrates the vulnerability pattern represented by
`MBEDTLS-POC-0020`: RSA DER parser acceptance of bytes appended after the
top-level ASN.1 `SEQUENCE`.

The normalized pattern is:

- Source PoC: `MBEDTLS-POC-0020`
- Source library: mbedTLS 4.1.0
- Source API: `mbedtls_pk_parse_key`
- Source internal APIs:
  - `mbedtls_rsa_parse_key`
  - `mbedtls_rsa_parse_pubkey`
- Target library: OpenSSL 3.5.5
- Target APIs:
  - `d2i_PrivateKey`
  - `d2i_RSAPrivateKey`
  - `d2i_RSA_PUBKEY`
- Harness family: `der_pointer_consumption`

## Vulnerability Pattern

The test input is a syntactically valid RSA DER object followed by extra bytes.
The key question is whether the parser treats the whole input buffer as one
object that must be consumed exactly, or whether it accepts the first DER object
and leaves trailing bytes unconsumed.

The migration target is not a memory-corruption condition. It is a semantic
boundary condition around exact DER input consumption.

## Oracle

The harness family is `der_pointer_consumption`.

For mbedTLS, safe behavior is:

```text
[OK] parser rejected trailing garbage.
```

or:

```text
[INFO] parser rejected trailing garbage with alternate ret=...
```

For OpenSSL `d2i_*` targets, the semantic bug-candidate signal is:

```text
ret=0
consumed_len < der_len
[BUG] target decoded first DER object but left trailing garbage unconsumed.
```

In these generated harnesses, `ret=0` means the OpenSSL adapter considered the
decode successful. The adapter also computes pointer consumption using the
advanced `const unsigned char *p` value supplied through `ppin`.

## Why This Is Not A Crash

The `bug_candidate` verdict here does not mean:

- ASan crash
- UBSan crash
- segmentation fault
- out-of-bounds memory write
- canary corruption

The OpenSSL cases exit with nonzero status because the harness intentionally
returns `1` when the semantic oracle detects partial consumption:

```text
ret=0
der_len=103
consumed_len=101
[BUG] target decoded first DER object but left trailing garbage unconsumed.
```

This is an oracle-driven semantic finding, not a sanitizer finding.

## Why This Is A Migrated Bug Candidate

The migrated pattern compares two behaviors under the same abstract input shape:

- mbedTLS 4.1.0 rejects the DER object with trailing bytes.
- OpenSSL `d2i_PrivateKey` and `d2i_RSAPrivateKey` decode the leading DER object
  and leave trailing bytes unconsumed.

That gives the cross-library migration signal:

```text
source verdict: safe_reject_behavior
target verdict: bug_candidate
migration verdict: migrated_bug_candidate
```

The important property is not that OpenSSL is memory-unsafe. The important
property is that the target API can preserve the vulnerability-pattern boundary:
valid DER prefix plus attacker-controlled trailing bytes, with the consumed
pointer exposing whether the full input was consumed.

## Final Results

After target-aware case filtering:

```text
total_cases: 54
raw_status_counts: {'run_ok': 36, 'run_nonzero': 18}
verdict_counts: {'safe_reject_behavior': 27, 'bug_candidate': 18, 'normal_behavior_needs_triage': 9}
total_pairs: 27
migration_verdict_counts: {'migrated_bug_candidate': 18, 'migration_needs_triage': 9}
```

All 54 rendered C cases compiled successfully.

The 18 `bug_candidate` cases are semantic pointer-consumption findings. They are
not crash findings.

## Representative Logs

mbedTLS safe rejection:

```text
DER kind: private
Parse API kind: rsa_private
DER length with trailing garbage: 103
Trailing garbage length: 2
ret=-135
expected_buggy=0
expected_fixed_or_safe=-135
[OK] parser rejected trailing garbage.
```

OpenSSL migrated bug candidate:

```text
ret=0
der_len=103
consumed_len=101
[BUG] target decoded first DER object but left trailing garbage unconsumed.
```

OpenSSL public-key path triage/safe-like rejection example:

```text
ret=-1
der_len=142
consumed_len=0
[OK] target rejected trailing-garbage input.
```

## Limitations

OpenSSL `d2i_*` APIs expose the consumed pointer through `ppin`. A caller can
avoid accepting trailing garbage by checking:

```c
p == der + der_len
```

Therefore, this result is best reported as an API usage semantic candidate. It
does not directly imply a CVE, and it does not mean OpenSSL is memory-unsafe in
these cases. The migrated finding is that the target API can successfully decode
a DER prefix while leaving trailing bytes for the caller to notice and reject.

## Reproduction

Run:

```bash
bash scripts/run_0020_rsa_der_pipeline.sh
```

The script regenerates cross templates, renders cases, compiles and runs the
harnesses, and writes:

- `runner/results/run_rsa_der_trailing_garbage_410.jsonl`
- `runner/results/run_rsa_der_trailing_garbage_410.summary.json`
- `runner/results/run_rsa_der_trailing_garbage_410.verdicts.jsonl`
- `runner/results/run_rsa_der_trailing_garbage_410.migration_summary.json`
- `runner/results/run_rsa_der_trailing_garbage_410.migration_pairs.jsonl`
