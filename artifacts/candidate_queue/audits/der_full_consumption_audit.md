# DER Full-Consumption Evidence Audit

## Conclusion

The existing local artifacts support a DER app-level validation gap candidate, not a crash and not a confirmed CVE.

## Evidence

- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/results/behavior_summary.json`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_der_gap_overall_summary.json`
- `artifacts/triage/ossl_store_full_consumption/results/app_level_security_commands/command_summary.json`

The controlled command-level evidence shows that valid DER with malformed trailing ASN.1 bytes can still be accepted by OpenSSL app-level commands and converted into normal output artifacts, while malformed-only inputs are rejected. This is consistent with a full-consumption semantic gap at an application boundary.

## Triage Limits

- No ASAN/UBSAN/SEGV evidence is present.
- The result should be described as `app_level_validation_gap_candidate`.
- Impact, documentation expectations, and minimal reproduction scope still need manual confirmation.
