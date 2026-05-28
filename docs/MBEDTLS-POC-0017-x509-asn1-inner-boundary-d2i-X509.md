# MBEDTLS-POC-0017: X.509 ASN.1 Inner-Boundary Migration To OpenSSL d2i_X509

## Overview

- Source pattern: `X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY`
- Source API: `mbedtls_x509_crt_parse_der`
- Target API: OpenSSL `d2i_X509`
- Harness family: `x509_asn1_inner_boundary`
- Oracle type: `inner_asn1_boundary_semantic_oracle`

This experiment migrates the X.509 / ASN.1 nested-substructure boundary pattern
from the mbedTLS public certificate parser to OpenSSL's DER X.509 parser. The
target harness observes whether `d2i_X509()` accepts or rejects the malformed
certificate and records pointer-consumption information through `consumed_len`.

## Historical Oracle Versus Current Runner Oracle

The original commit-level evidence records a differential mbedTLS oracle:

- buggy ret=`-9186`
- fixed ret=`-9184`

Those values come from the original buggy/fixed commit worktrees and represent
the historical parser-boundary difference:

- buggy: parser crosses the inner ASN.1 substructure boundary;
- fixed: parser obeys the inner boundary and returns an out-of-data style error.

In the current mbedTLS 4.1.0 runner environment, both the original PoC and the
rendered source harness return:

```text
ret=-96
```

`ret=-96` is `MBEDTLS_ERR_ASN1_OUT_OF_DATA`, a lower-level ASN.1 error. This is
an early safe rejection in the current public API path, not a crash.

Therefore the historical `-9186` / `-9184` oracle should not be forced onto the
current mbedTLS 4.1.0 run. To reproduce those exact values, use the original
buggy/fixed commits or the original reproduction environment.

## Current Result

Rendered and executed cases:

```text
total_cases: 16
raw_status_counts: {'run_ok': 16}
verdict_counts: {'safe_reject_behavior': 16}
total_pairs: 8
migration_verdict_counts: {'migrated_safe': 8}
```

Per-library interpretation:

- mbedTLS 4.1.0: `safe_reject_behavior`
- OpenSSL `d2i_X509`: `safe_reject_behavior`
- Migration result: `migrated_safe`

There is no `bug_candidate` in this run. There is also no crash signal: no ASan,
UBSan, SEGV, or sanitizer crash was observed in the generated case results.

## Conclusion

The OpenSSL `d2i_X509` migration currently forms a safe/safe comparison group.
It should not be reported as a migrated vulnerability.

This is still a useful negative result for the migration framework: it shows
that the pipeline can preserve a vulnerability-path experiment, run both source
and target harnesses, and classify a cross-library candidate as not reproducing
the historical issue in the current tested versions.

Future work can test `ASN1_item_d2i`, which is closer to the lower-level ASN.1
item parsing layer than `d2i_X509`. That follow-up should still keep the
historical commit-level oracle separate from the current-version runner oracle.
