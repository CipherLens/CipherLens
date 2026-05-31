# MBEDTLS-POC-0027: TLS 1.3 verify_result Flag Propagation

## Migration Status

**status: migration_not_applicable / framework_limitation / needs_tls_handshake_harness**

This PoC cannot be directly migrated under the current unified recipe-slot single-process
C harness framework. No `run_recipe.*` result files are present. See sections below.

---

## 1. Source Pattern Summary

| Field | Value |
|---|---|
| POC | MBEDTLS-POC-0027 |
| Template ID | TLS13_VERIFY_RESULT_KEY_USAGE_PROPAGATION |
| CVE | CVE-2024-45159 |
| Source library | mbedTLS |
| Affected API | `mbedtls_ssl_get_verify_result` |
| Direct mutation file | `library/ssl_tls13_generic.c` |
| Direct mutation function | `ssl_tls13_validate_certificate` |
| Vulnerability class | `tls_verify_result_semantic` |
| Oracle type | `verify_result_flag_semantic_oracle` |
| Fix commit | ef41d8ccbe91c5c59e32f47ceda3365525c47124 |
| Pattern YAML | knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0027.yaml |

**Failure signal:**
TLS 1.3 certificate keyUsage/extKeyUsage verification failure is detected internally in
`ssl_tls13_validate_certificate` but the corresponding flags are **not propagated** into
`ssl->session_negotiate->verify_result`, causing `mbedtls_ssl_get_verify_result()` to
return 0 (no failures) when the following flags should be set:

- `MBEDTLS_X509_BADCERT_KEY_USAGE`
- `MBEDTLS_X509_BADCERT_EXT_KEY_USAGE`

**Root cause summary:**

In the buggy version, `ssl_tls13_validate_certificate()` detects a keyUsage extension mismatch
(e.g., RSA certificate with KeyEncipherment usage presented during TLS 1.3 authentication
where digital signature is expected) but does not write the corresponding
`MBEDTLS_X509_BADCERT_KEY_USAGE` bit into `ssl->session_negotiate->verify_result`.
The caller calling `mbedtls_ssl_get_verify_result()` after the handshake therefore reads 0
instead of the expected failure bitmask.

**Core vulnerability path (must be preserved for any migration):**

```
TLS 1.3 client-certificate handshake
    ↓
ssl_tls13_validate_certificate() detects keyUsage extension mismatch
    ↓
[BUGGY] MBEDTLS_X509_BADCERT_KEY_USAGE NOT written to ssl->session_negotiate->verify_result
    ↓
mbedtls_ssl_get_verify_result() returns 0 (or missing flag)
    ↓
caller observes missing expected flag → bug detected
```

**Buggy vs fixed behavior:**

| Observable | Buggy version | Fixed version |
|---|---|---|
| ssl_tls13_validate_certificate detects mismatch | YES | YES |
| MBEDTLS_X509_BADCERT_KEY_USAGE written to verify_result | **NO** | YES |
| mbedtls_ssl_get_verify_result() returns failure flags | **NO (returns 0)** | YES |
| ssl-opt.sh output contains `! Usage does not match the keyUsage extension` | **absent** | present |

---

## 2. Original Reproduction Method

- **Regression test:** `tests/ssl-opt.sh`
- **Related test file:** `tests/suites/test_suite_ssl.data`
- **Test case name:** `keyUsage cli-auth 1.3: RSA, KeyEncipherment: fail (soft)`
- **Has standalone C PoC:** NO
- **Requires TLS 1.3 handshake:** YES
- **Requires certificate chain:** YES (client RSA certificate with incompatible keyUsage)
- **Requires server-client dual process:** YES (ssl-opt.sh spawns server + client)
- **Observed buggy output:**

```
keyUsage cli-auth 1.3: RSA, KeyEncipherment: fail (soft) .......... FAIL
! pattern '! Usage does not match the keyUsage extension' MUST be present in the Server output
FAILED (0 / 1 tests (0 skipped))
exit_code=1
```

This PoC is **not** a plain single-function C harness. It depends on:
1. A TLS 1.3 handshake between server and client
2. A client certificate with a specific incompatible keyUsage extension (RSA KeyEncipherment)
3. The server running `ssl_tls13_validate_certificate` during the handshake
4. Observation of `mbedtls_ssl_get_verify_result()` after the handshake completes

These requirements cannot be expressed by a single-process call sequence of the form
`init → trigger → oracle → cleanup`.

---

## 3. API Suitability Scoring

Scoring formula from `migration/candidate_mapper.py`:

```
final_score = 0.15 * operation_family
            + 0.20 * function_behavior
            + 0.20 * parameter_structure
            + 0.30 * vulnerability_path
            + 0.15 * harness_feasibility
```

Decision thresholds:
- `final_score >= 75 AND vulnerability_path >= 70` → `generate`
- `final_score >= 55 AND vulnerability_path >= 50` → `needs_llm_review`
- otherwise → `skip / migration_not_applicable`

---

### Candidate A: OpenSSL TLS handshake-level path

```
target_library: openssl
target_api_or_path:
  - SSL_CTX_new / SSL_new / SSL_connect / SSL_accept
  - SSL_get_verify_result
  - X509_STORE_CTX_get_error (within verify callback)
  - memory BIO (BIO_s_mem) or client/server dual-side TLS 1.3 handshake
operation_family: tls_certificate_verification_result_propagation
```

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 85 | Both are TLS certificate verification result APIs; SSL_get_verify_result ↔ mbedtls_ssl_get_verify_result |
| function_behavior | 75 | Post-handshake caller-visible verification result getter; same abstract contract |
| parameter_structure | 55 | SSL* ↔ mbedtls_ssl_context*; structurally different but conceptually mappable |
| vulnerability_path | 60 | OpenSSL TLS 1.3 also validates keyUsage via its own path (ssl_verify_cert_chain → SSL_get_verify_result). However: (1) OpenSSL does not have the same flag-propagation bug; (2) cannot demonstrate source-buggy vs target-bug-candidate using a common "buggy" code path; (3) the comparison would be mbedTLS-buggy vs OpenSSL-correct, which requires TLS infrastructure, not just API semantics |
| harness_feasibility | 30 | Requires: memory BIO TLS 1.3 loopback, embedded RSA certificate with incompatible keyUsage, CA certificate, multi-step handshake loop with BIO state management — not supported by current single-process recipe-slot runner |

**Weighted score:** 0.15×85 + 0.20×75 + 0.20×55 + 0.30×60 + 0.15×30 = 12.75 + 15.0 + 11.0 + 18.0 + 4.5 = **61.25**

```
operation_family: tls_certificate_verification_result_propagation
parameter_structure_match: partial — SSL* vs mbedtls_ssl_context*, different setup pipelines
vulnerability_path_preservation: partial — same abstract concept, but OpenSSL lacks the bug;
  would require TLS 1.3 memory BIO harness to observe equivalent verify_result propagation
oracle_observability: conditional — SSL_get_verify_result() is observable post-handshake if
  handshake infrastructure exists; X509_STORE_CTX_get_error observable in verify callback
harness_feasibility: low — requires TLS 1.3 memory BIO loopback, certificate fixtures,
  multi-step handshake protocol; not achievable with current single-process recipe runner

preserved_features:
  - same caller-visible API contract: read verify result after handshake
  - same trigger class: keyUsage extension mismatch in client certificate
  - same oracle concept: expected flag present or absent in verify result

lost_or_weakened_features:
  - OpenSSL does not have the equivalent flag-propagation bug in its TLS 1.3 path
  - Cannot construct source-buggy / target-bug-candidate cross-library pair
  - Requires TLS handshake infrastructure not supported by current framework
  - Requires embedded test certificates with specific extension constraints
  - Memory BIO TLS 1.3 handshake is a significant new framework component

score: 61.25
decision: needs_tls_handshake_harness
reason: >
  Numerically reaches needs_llm_review range (61.25 >= 55) but vulnerability_path=60 < 70
  (generate threshold not met). Critically, harness_feasibility=30 blocks automatic generation.
  TLS 1.3 memory BIO handshake with embedded certificates is a significant framework extension
  beyond the current single-process recipe-slot runner. This is a framework limitation.
```

---

### Candidate B: OpenSSL X.509 verify API path

```
target_library: openssl
target_api_or_path:
  - X509_verify_cert
  - X509_STORE_CTX_init / X509_STORE_CTX_new
  - X509_STORE_CTX_get_error
  - X509_check_purpose / keyUsage / extKeyUsage checks
operation_family: x509_certificate_chain_verification
```

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 60 | X.509 certificate verification is related but different abstraction layer from TLS verify_result |
| function_behavior | 45 | X509_verify_cert checks a certificate chain in a store context; mbedtls_ssl_get_verify_result reads a TLS-session-level result. Different abstraction. |
| parameter_structure | 40 | Completely different setup: mbedtls_ssl_context* vs X509_STORE_CTX*; no direct parameter mapping |
| vulnerability_path | 30 | CRITICAL LOSS: The original bug is in `ssl_tls13_validate_certificate` — the TLS 1.3 handshake path. X509_verify_cert uses an entirely different code path for keyUsage verification and correctly reports keyUsage failures via X509_STORE_CTX error codes independently. Cannot distinguish buggy mbedTLS from fixed mbedTLS using standalone X509_verify_cert. Cannot observe the TLS 1.3 flag-propagation failure at all. |
| harness_feasibility | 65 | X509_verify_cert can be used in a single-process harness; requires constructing a certificate chain with specific keyUsage extensions, but feasible |

**Weighted score:** 0.15×60 + 0.20×45 + 0.20×40 + 0.30×30 + 0.15×65 = 9.0 + 9.0 + 8.0 + 9.0 + 9.75 = **44.75**

```
operation_family: x509_certificate_chain_verification
parameter_structure_match: none — completely different context objects and setup
vulnerability_path_preservation: very weak — X509_verify_cert has its own correct keyUsage
  verification path unrelated to TLS 1.3 ssl_tls13_validate_certificate flag propagation
oracle_observability: limited — X509_STORE_CTX_get_error can observe keyUsage errors,
  but this reflects X509_verify_cert's own logic, not the TLS 1.3 flag-propagation path
harness_feasibility: moderate — single-process harness is feasible but would not test
  the target vulnerability

preserved_features:
  - related to certificate verification
  - keyUsage can be tested through X509_verify_cert path

lost_or_weakened_features:
  - X509_verify_cert does NOT exercise TLS 1.3 ssl_tls13_validate_certificate code path
  - X509_verify_cert already correctly reports keyUsage errors through its own path
  - Cannot demonstrate caller-visible verify_result flag propagation failure
  - No mbedtls_ssl_get_verify_result() equivalent in standalone X.509 verify path
  - Missing TLS 1.3 handshake context entirely
  - Would be a weak semantic projection at best, not a strong migration

score: 44.75
decision: migration_not_applicable
reason: >
  Score 44.75 < 55 threshold; vulnerability_path=30 < 50. The standalone X.509 verify path
  cannot express TLS 1.3 ssl_tls13_validate_certificate flag-propagation behavior.
  X509_verify_cert correctly reports keyUsage failures via its own independent code path,
  which is irrelevant to whether TLS 1.3 handshake flag propagation works correctly.
  Migrating to this API loses the entire core vulnerability path.
  Maximum classification: weak semantic projection. Not a valid migration target.
```

---

### Candidate C: OpenSSL parse-only APIs

```
target_library: openssl
target_api_or_path:
  - d2i_X509
  - PEM_read_bio_X509
operation_family: x509_der_or_pem_parsing
```

| Dimension | Score | Rationale |
|---|---|---|
| operation_family | 15 | DER/PEM parsing is a completely different operation from TLS verify_result flag propagation |
| function_behavior | 10 | Certificate parsing only; does not verify keyUsage, does not run a handshake |
| parameter_structure | 10 | No meaningful parameter mapping to source API |
| vulnerability_path | 0 | Zero: parsing APIs do not perform keyUsage verification and do not expose verify_result flags in any form |
| harness_feasibility | 80 | Easily usable in single-process harness, but harness cannot test the target vulnerability at all |

**Weighted score:** 0.15×15 + 0.20×10 + 0.20×10 + 0.30×0 + 0.15×80 = 2.25 + 2.0 + 2.0 + 0.0 + 12.0 = **18.25**

```
operation_family: x509_der_or_pem_parsing
parameter_structure_match: none
vulnerability_path_preservation: none — parsing APIs perform no keyUsage verification
  and do not expose any verify_result flags
oracle_observability: none relevant to this vulnerability
harness_feasibility: high, but harness tests nothing relevant to 0027

preserved_features:
  - none relevant to the vulnerability path

lost_or_weakened_features:
  - no keyUsage verification performed
  - no TLS handshake
  - no verify_result flag observable
  - completely wrong abstraction layer

score: 18.25
decision: reject
reason: >
  Score 18.25, vulnerability_path=0. Parsing APIs provide no coverage of TLS 1.3 verify_result
  flag propagation. d2i_X509 and PEM_read_bio_X509 only parse certificates; they do not perform
  keyUsage verification and do not expose any verify_result flags. Rejected entirely.
```

---

### Scoring Summary Table

| Candidate | op_fam | func_beh | param_struct | vuln_path | harness_feas | Final Score | Decision |
|---|---|---|---|---|---|---|---|
| A: SSL_get_verify_result (TLS 1.3 memory BIO) | 85 | 75 | 55 | 60 | 30 | **61.25** | needs_tls_handshake_harness |
| B: X509_verify_cert | 60 | 45 | 40 | 30 | 65 | **44.75** | migration_not_applicable |
| C: d2i_X509 / PEM_read_bio_X509 | 15 | 10 | 10 | 0 | 80 | **18.25** | reject |

**No candidate reaches the `generate` threshold (final_score >= 75 AND vuln_path >= 70).**

The best candidate (A, score 61.25) is blocked by two independent constraints:
1. `vulnerability_path = 60 < 70` (generate threshold not met)
2. `harness_feasibility = 30` — current single-process recipe-slot framework cannot implement TLS 1.3 memory BIO handshake with embedded certificate fixtures

---

## 4. Migration Applicability Conclusion

**Status:** `migration_not_applicable` / `framework_limitation` / `needs_tls_handshake_harness`

The best available candidate (OpenSSL SSL_get_verify_result via memory BIO TLS 1.3 handshake)
reaches a weighted score of 61.25 but does not meet the generate threshold.
All three candidate classes fail to reach the `generate` threshold.

The fundamental issue is a **framework limitation**: the current unified recipe-slot framework
supports only single-process C harnesses with a direct API call sequence. MBEDTLS-POC-0027
requires a TLS 1.3 handshake infrastructure that is beyond the scope of the current framework.

This result is **not** `migrated_safe` and is **not** `migrated_bug_candidate`.
No harness was run; no `run_recipe.*` result files are created for this PoC.

---

## 5. Why Ordinary X.509 APIs Cannot Substitute

### Why `d2i_X509` and `PEM_read_bio_X509` are rejected:

These APIs only parse certificate bytes from DER or PEM format into an `X509` struct.
They perform **no** keyUsage verification and expose **no** verify_result flags.
Using them would test certificate DER/PEM parsing, which is entirely irrelevant to
the 0027 root cause (TLS 1.3 ssl_tls13_validate_certificate flag propagation).
This is a different vulnerability family (`x509_asn1_inner_boundary` or `der_pointer_consumption`)
from `tls_verify_result_semantic`. **Rejected outright (score 18.25).**

### Why `X509_verify_cert` is not a valid migration target:

`X509_verify_cert` can express general certificate chain verification including keyUsage checks.
However:

1. The 0027 root cause is specifically in the **TLS 1.3 code path** (`ssl_tls13_validate_certificate`),
   not in the general X.509 verification path.
2. `X509_verify_cert` in OpenSSL uses its own independent keyUsage checking path
   (`x509_check_key_usage` called from `check_cert`), which correctly reports errors through
   `X509_STORE_CTX_get_error`. This path is separate from and unrelated to TLS 1.3 flag propagation.
3. There is no `mbedtls_ssl_get_verify_result()` equivalent in the standalone X.509 verify path.
   The observable `X509_STORE_CTX_get_error` reflects X509_verify_cert's own result, not any
   TLS-session-level verify_result accumulation.
4. Even if `X509_verify_cert` correctly reports keyUsage failures, this **cannot distinguish**
   buggy mbedTLS (where the TLS 1.3 flag propagation path is broken) from fixed mbedTLS
   (where the flag propagation is correct). The comparison would be meaningless.
5. Maximum classification: **weak semantic projection** — the concept of keyUsage verification
   is preserved but the specific vulnerability path (TLS 1.3 flag propagation to verify_result)
   is lost entirely.

**Conclusion:** `X509_verify_cert` is `migration_not_applicable` (score 44.75, vuln_path=30).
Migrating to this API would not reproduce or detect the 0027 bug class.

---

## 6. Recommended Future Framework Extension

To support MBEDTLS-POC-0027 and future TLS handshake-level semantic PoCs, a new harness
family should be defined:

### New harness family: `tls_verify_result_semantic`

```yaml
harness_family: tls_verify_result_semantic
description: >
  TLS/certificate verification should propagate verification failure flags into the
  caller-visible result API. Bug: internal detection of certificate extension failure
  without caller-visible propagation to the verify_result interface.
oracle_types:
  - certificate_verify_result_flag_oracle
required_observables:
  - handshake_result_code
  - verify_result_flags
  - expected_failure_flag_bitmask
  - certificate_usage_constraints
required_infrastructure:
  - tls_memory_bio_loopback         # BIO_s_mem server + client in one process
  - embedded_test_certificates       # pre-built DER, RSA cert with incompatible keyUsage
  - tls13_handshake_loop             # SSL_do_handshake iteration until complete
safe_behavior:
  condition: invalid certificate usage is detected AND reflected in caller-visible verify result
  description: >
    After handshake, SSL_get_verify_result() / mbedtls_ssl_get_verify_result() returns
    the expected failure flags (e.g., X509_V_ERR_KEY_USAGE_NO_DIGITAL_SIGNATURE,
    MBEDTLS_X509_BADCERT_KEY_USAGE)
bug_behavior:
  condition: invalid certificate usage detected internally but NOT reflected in verify result
  description: >
    Handshake completes (possibly soft-fail) but caller-visible verify result is 0 or
    missing expected flag, indicating flag propagation failure in the TLS code path
triage_behavior:
  condition: handshake fails hard before reaching verify_result check
  description: >
    Error path terminates handshake before verify_result accumulation; oracle not reached;
    needs oracle tightening or authentication mode adjustment
```

### Required framework additions

1. **TLS memory BIO loopback harness template** — server + client SSL contexts connected
   via `BIO_s_mem`, runs handshake loop in one process without network sockets
2. **Embedded DER-encoded test certificate fixtures** — RSA certificate with RSA KeyEncipherment
   keyUsage (incompatible with TLS 1.3 signing), signed by a test CA; stored as C byte arrays
3. **Certificate generation or pre-generated fixtures** — either scripts using openssl CLI
   or pre-built DER arrays to avoid runtime certificate generation in harness
4. **`cross_generator_from_adapters.py` renderer** — new renderer for `tls_verify_result_semantic`
   harness family that generates TLS memory BIO handshake C code
5. **`analyze_results.py` oracle interpreter** — new oracle for `certificate_verify_result_flag_oracle`
   that checks whether expected verify_result flag bits are set or missing
6. **`adapter_validate.py` family-level validation rules** — validate that adapters for this
   family include required TLS setup fields and correct oracle observables

### Target API for first implementation (Candidate A):

```
target_library: openssl
source_mbedtls_api: mbedtls_ssl_get_verify_result
target_openssl_api: SSL_get_verify_result
handshake_infrastructure: BIO_s_mem memory BIO loopback
certificate_fixture: RSA cert with keyUsage=RSA KeyEncipherment (OID 2.5.29.15)
expected_oracle: SSL_get_verify_result() returns non-zero OR
                 X509_STORE_CTX verify callback records X509_V_ERR_KEY_USAGE_NO_DIGITAL_SIGNATURE
```

---

## References

- CVE: CVE-2024-45159
- Advisory: https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2024-08-3/
- Fix commit: ef41d8ccbe91c5c59e32f47ceda3365525c47124
- Buggy commit: ef41d8ccbe91c5c59e32f47ceda3365525c47124^
- Mutation file: `library/ssl_tls13_generic.c` (`ssl_tls13_validate_certificate`)
- Regression test: `tests/ssl-opt.sh` ("keyUsage cli-auth 1.3: RSA, KeyEncipherment: fail (soft)")
- Related test: `tests/suites/test_suite_ssl.data`
- Pattern YAML: `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0027.yaml`
- Reproduction notes: `data/pocs/core10/MBEDTLS-POC-0027/notes.md`
- Reproduction result: `data/pocs/core10/MBEDTLS-POC-0027/reproduction_result.md`
- Fix commits list: `data/pocs/core10/MBEDTLS-POC-0027/fix_commits.txt`
