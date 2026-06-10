# CMAC Double-Final Lifecycle Triage

This triage isolates the four strongest MAC lifecycle divergence cases from the
main recipe-slot chain:

- `AES-128-CBC + setup_final_final`
- `AES-128-CBC + setup_update_final_final`
- `AES-256-CBC + setup_final_final`
- `AES-256-CBC + setup_update_final_final`

The minimal cases are:

- `cases/min_cmac_double_final_openssl.c`
- `cases/min_cmac_double_final_mbedtls.c`

Outputs:

- `results/cmac_double_final_results.txt`
- `results/cmac_double_final_summary.json`
- `results/cmac_lifecycle_doc_review.md`

Interpretation:

- This is not a crash.
- This is not currently a CVE claim.
- OpenSSL CMAC allows repeated `EVP_MAC_final()` and continued operation in
  these minimal cases.
- mbedTLS PSA rejects repeated `psa_mac_sign_finish()` after a successful
  finish with `PSA_ERROR_BAD_STATE`.
- The current classification is `lifecycle_semantic_divergence_candidate`.
- This needs OpenSSL documentation/source review before deciding whether it is
  allowed legacy semantics or a reportable lifecycle validation issue.
