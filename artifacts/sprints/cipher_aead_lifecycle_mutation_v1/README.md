# cipher_aead_lifecycle_mutation_v1

This sprint selects 12 OpenSSL EVP AEAD/GCM lifecycle cases from the prior 24-case draft and runs only the selected control/mutation set.

Key outputs:

- `mutation/selected_aead_cases.yaml`
- `source_template/openssl_evp_aead_lifecycle_template.c`
- `rendered_cases/`
- `results/run.jsonl`
- `analysis/aead_lifecycle_analysis.json`
- `reports/cipher_aead_lifecycle_mutation_report.md`

No AFL++ run, GLM free-form C generation, commit, push, or confirmed vulnerability claim is part of this sprint.
