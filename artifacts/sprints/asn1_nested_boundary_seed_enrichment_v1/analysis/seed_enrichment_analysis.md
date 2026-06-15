# Seed Enrichment Analysis

- classification: `real_seed_not_found`, `equivalent_seed_not_generated`, `generated_seed_parse_error_no_crash`, `blocked_seed_missing`, `blocked_high_uncertainty_reconstruction`, `not_enough_for_claim`
- strict_reproduction_success: `false`
- crash_candidate: `false`
- confirmed_vulnerability: `false`

Bounded enrichment found related OpenSSL PBMAC1 malformed salt test vectors, but not the original `/tmp/pbmac1_null_salt.p12`. The related vectors produce safe parse/mac-generation errors on OpenSSL 3.5.5 and do not reproduce a crash.

ASN.1 line status: `blocked_seed_missing`.
