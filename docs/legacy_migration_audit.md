# Legacy Migration Audit

Date: 2026-05-29

This audit records the current state of already explored migration case studies and how they map to the newer `artifacts/migrations/<artifact_slug>/` layout. Old root-level outputs were not deleted or moved.

## Repository State

普通未提交改动存在，未发现 rebase/merge 冲突。当前未提交改动包括 0004 recipe/slot-filling 相关框架改动和新增 artifacts:

- `migration/adapter_filler.py`
- `migration/adapter_validate.py`
- `migration/evidence_collector.py`
- `runner/analyze_results.py`
- `runner/compile_run.py`
- `template_maker/cross_generator_from_adapters.py`
- `template_maker/render_cases.py`
- `adapter_recipes/`
- `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/`
- `config/harness_families.yaml`
- `docs/harness_family_design.md`
- `migration_candidates/cipher/`
- `normalized_templates/cipher/`

## Discovery Summary

Pattern files exist for:

- `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0001.{yaml,md}`
- `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0002.{yaml,md}`
- `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0004.{yaml,md}`
- `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0017.{yaml,md}`
- `knowledge_raw/poc_patterns/mbedtls/MBEDTLS-POC-0020.{yaml,md}`

Normalized templates discovered:

- `normalized_templates/bignum/mpi_write_string`
- `normalized_templates/bignum/mpi_sub_abs`
- `normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow`
- `normalized_templates/x509/x509_asn1_inner_boundary`
- `normalized_templates/rsa/rsa_der_trailing_garbage`

## Per-PoC Audit

| PoC | template_id | category / slug | harness_family | oracle_type | current migration status | recommended next action |
| --- | --- | --- | --- | --- | --- | --- |
| `MBEDTLS-POC-0001` | `BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER` | `bignum/mpi_write_string` | legacy bignum / buffer boundary | legacy canary / return-code behavior | `complete_runnable` in legacy root layout | Re-run or copy into `artifacts/migrations/mbedtls-poc-0001-mpi-write-string/` using existing validated adapters when ready. |
| `MBEDTLS-POC-0002` | `BIGNUM_MPI_SUB_ABS_LIMB_BOUNDARY` | `bignum/mpi_sub_abs` | not recorded in template meta | not recorded in template meta | `evidence_only` | Needs adapter generation/validation before cross template generation. Do not hard-code generator fixes just for this PoC. |
| `MBEDTLS-POC-0004` | `CIPHER_PKCS_PADDING_INVALID_OUTLEN_UNDERFLOW` | `cipher/cipher_pkcs_padding_outlen_underflow` | `return_code_outlen_semantic` | `invalid_padding_output_length_oracle` | `complete_runnable` in new artifact layout | Keep as reference implementation for recipe/slot-filling flow. |
| `MBEDTLS-POC-0017` | `X509_ASN1_INNER_SUBSTRUCTURE_BOUNDARY` | `x509/x509_asn1_inner_boundary` | `x509_asn1_inner_boundary` | `inner_asn1_boundary_semantic_oracle` | `complete_runnable` in new artifact layout | Keep as safe/safe negative migration case. |
| `MBEDTLS-POC-0020` | `RSA_DER_TOP_LEVEL_SEQUENCE_TRAILING_GARBAGE` | `rsa/rsa_der_trailing_garbage` | `der_pointer_consumption` | `pointer_consumption_semantic_oracle` | `complete_runnable` in new artifact layout | Keep as migrated semantic bug-candidate case. |

## Detailed Paths

### MBEDTLS-POC-0001

- Source template path: `normalized_templates/bignum/mpi_write_string`
- Candidate path: `migration_candidates/bignum/mpi_write_string/candidates.yaml`
- Evidence path: `migration_candidates/bignum/mpi_write_string/candidates_with_evidence.yaml`
- Adapter path: `adapters/BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER/`
- Validated adapter path: `adapters_validated/BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER/`
- Cross template paths:
  - `cross_templates_from_validated_adapters/BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER/`
  - older experimental roots also exist under `cross_templates_from_adapters/`, `cross_templates_from_selected_mask_adapters/`, and `cross_templates_from_candidates/`
- Rendered cases paths:
  - `rendered_cases_from_validated_adapters/BIGNUM_MPI_WRITE_STRING_NEGATIVE_SMALL_BUFFER/`
  - older experimental roots also exist.
- Result files:
  - `runner/results/run_cross_mpi_write_string.summary.json`
  - `runner/results/run_cross_mpi_write_string.migration_summary.json`
- Latest legacy result:
  - `verdict_counts`: `{'safe_behavior': 64}`
  - `migration_verdict_counts`: `{'migrated_safe': 32}`

### MBEDTLS-POC-0002

- Source template path: `normalized_templates/bignum/mpi_sub_abs`
- Candidate path: `migration_candidates/bignum/mpi_sub_abs/candidates.yaml`
- Evidence path: `migration_candidates/bignum/mpi_sub_abs/candidates_with_evidence.yaml`
- Adapter path: not found
- Validated adapter path: not found
- Cross template path: not found for this template
- Rendered cases path: not found for this template
- Result files: not found for this template
- Current status: `evidence_only`
- Recommended next action: generate and validate a structured adapter before attempting cross generation.

### MBEDTLS-POC-0004

- Source template path: `normalized_templates/cipher/cipher_pkcs_padding_outlen_underflow`
- Candidate path: `migration_candidates/cipher/cipher_pkcs_padding_outlen_underflow/candidates.yaml`
- Evidence paths:
  - `migration_candidates/cipher/cipher_pkcs_padding_outlen_underflow/candidates_with_evidence.yaml`
  - `migration_candidates/cipher/cipher_pkcs_padding_outlen_underflow/candidates_with_evidence.EVP_DecryptFinal_ex.via_target_api.yaml`
- Adapter paths:
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/adapters/`
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/adapters_recipe_llm/`
- Validated adapter paths:
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/adapters_validated/`
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/adapters_recipe_llm_validated/`
- Cross template path: `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/cross_templates_recipe/`
- Rendered cases path: `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/rendered_cases_recipe/`
- Result files:
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/results/run_recipe.summary.json`
  - `artifacts/migrations/mbedtls-poc-0004-cipher-pkcs-padding-outlen-underflow/results/run_recipe.migration_summary.json`
- Result:
  - `verdict_counts`: `{'safe_reject_behavior': 8}`
  - `migration_verdict_counts`: `{'migrated_safe': 4}`

### MBEDTLS-POC-0017

- Source template path: `normalized_templates/x509/x509_asn1_inner_boundary`
- Candidate path: `migration_candidates/x509/x509_asn1_inner_boundary/candidates.yaml`
- Evidence paths:
  - `migration_candidates/x509/x509_asn1_inner_boundary/candidates_with_evidence.yaml`
  - `migration_candidates/x509/x509_asn1_inner_boundary/candidates_with_evidence.d2i_X509.yaml`
- Adapter path: `adapters_x509_asn1_inner_boundary_d2i_X509/`
- Validated adapter path: `adapters_x509_asn1_inner_boundary_d2i_X509_validated/`
- New cross template path: `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/cross_templates/`
- New rendered cases path: `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/rendered_cases/`
- New result files:
  - `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/results/run.summary.json`
  - `artifacts/migrations/mbedtls-poc-0017-x509-asn1-inner-boundary-d2i-x509/results/run.migration_summary.json`
- Result:
  - `verdict_counts`: `{'safe_reject_behavior': 16}`
  - `migration_verdict_counts`: `{'migrated_safe': 8}`

### MBEDTLS-POC-0020

- Source template path: `normalized_templates/rsa/rsa_der_trailing_garbage`
- Candidate path: `migration_candidates/rsa/rsa_der_trailing_garbage/candidates.yaml`
- Evidence path: `migration_candidates/rsa/rsa_der_trailing_garbage/candidates_with_evidence.yaml`
- Validated adapter path: `adapters_rsa_validated/`
- New cross template path: `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/cross_templates/`
- New rendered cases path: `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/rendered_cases/`
- New result files:
  - `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/results/run.summary.json`
  - `artifacts/migrations/mbedtls-poc-0020-rsa-der-trailing-garbage/results/run.migration_summary.json`
- Result:
  - `verdict_counts`: `{'safe_reject_behavior': 27, 'bug_candidate': 18, 'normal_behavior_needs_triage': 9}`
  - `migration_verdict_counts`: `{'migrated_bug_candidate': 18, 'migration_needs_triage': 9}`

## Notes

- `MBEDTLS-POC-0017` is a safe/safe result and should not be reported as a vulnerability.
- `MBEDTLS-POC-0020` contains semantic migrated bug candidates based on DER pointer consumption, not crashes.
- `MBEDTLS-POC-0004` is a safe/safe result for the currently tested `EVP_DecryptFinal_ex` recipe path.
- Old root-level directories such as `adapters_*`, `cross_templates_*`, `rendered_cases_*`, and `runner/results/run_*` were left untouched.
