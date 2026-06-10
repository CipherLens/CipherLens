# App-Level DER Full-Consumption Gap Overall Summary

Classification:

```text
real_app_level_validation_gap_candidate
```

This is a semantic validation-gap candidate, not a crash and not a confirmed CVE.

Malformed tail:

```text
30 82 10 00
```

## Summary Table

| object/command area | tested | baseline success | malformed-tail accepted | malformed-only rejected | classification |
| --- | --- | ---: | ---: | ---: | --- |
| x509 | yes | 2/2 | 2/2 | 2/2 | app_level_accepts_valid_prefix_with_malformed_tail |
| pkey/pkcs8 | yes | 2/2 | 2/2 | 2/2 | app_level_accepts_valid_prefix_with_malformed_tail |
| pubkey | yes | 1/1 | 1/1 | 1/1 | app_level_accepts_valid_prefix_with_malformed_tail |
| csr | yes | 3/3 | 3/3 | 3/3 | app_level_accepts_valid_prefix_with_malformed_tail |
| crl | yes | 2/2 | 2/2 | 2/2 | app_level_accepts_valid_prefix_with_malformed_tail |

## Boundary

- Low-level `d2i_*` prefix parsing is not enough by itself to claim an app-level issue.
- OSSL_STORE has object-stream semantics, so STORE-level acceptance needs caller context.
- The stronger finding is that user-facing app commands can fingerprint, export, or display a valid leading object while ignoring malformed ASN.1 trailing bytes.
- Since malformed-only inputs are rejected, the result is specifically valid-prefix acceptance, not arbitrary malformed input acceptance.

## Evidence Files

- `artifacts/triage/ossl_store_full_consumption/minimal_reproducer/results/minimal_command_summary.json`
- `artifacts/triage/ossl_store_full_consumption/csr_crl_boundary/results/csr_crl_command_summary.json`
- `minimal_reproducer/results/minimal_command_matrix.csv`
- `csr_crl_boundary/results/csr_crl_command_matrix.csv`
