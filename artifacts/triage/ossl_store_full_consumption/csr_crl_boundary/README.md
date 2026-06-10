# CSR / CRL DER Malformed Tail Boundary

This artifact checks whether the app-level DER malformed-tail behavior observed
for x509/pkey/pkcs8 extends to `openssl req` and `openssl crl`.

OpenSSL command:

```text
/home/wen/work/clean_sources/openssl-3.5.5/apps/openssl
```

Malformed tail:

```text
30 82 10 00
```

## Results

CSR:

```text
tested=True
baseline_success=3/3
malformed_tail_accepted=3/3
malformed_only_rejected=3/3
classification=app_level_accepts_valid_prefix_with_malformed_tail
```

CRL:

```text
tested=True
baseline_success=2
malformed_tail_accepted=2
malformed_only_rejected=2
classification=app_level_accepts_valid_prefix_with_malformed_tail
```

Detailed files:

```text
results/csr_crl_command_matrix.csv
results/csr_crl_command_summary.json
results/input_tail_hex.txt
logs/
```

Interpretation:

- `app_level_accepts_valid_prefix_with_malformed_tail` means baseline succeeds,
  valid-prefix plus malformed tail succeeds, and malformed-only fails.
- This is a semantic validation-gap candidate, not a crash and not a confirmed CVE.
