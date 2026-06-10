# MAC Lifecycle GLM Slot-Filling Verification

## Conclusion

- `adapter_filler_executed`: `true`
- `adapter_filler_used_llm`: `true`
- `adapter_filler_strict_recipe_mode`: `true`
- `_adapter_mode`: `recipe_slot_filling`
- `_llm_status`: `ok`
- `slot_bindings_present`: `true`
- `adapter_validate_status`: `ok`
- `can_claim_glm_used_in_a_path`: `true`
- `can_claim_full_a_path_compliant`: `false`

GLM/LLM slot-filling is now verified for the MAC lifecycle A-path adapter step. The generated adapter was produced by `migration.adapter_filler` with `--use-llm`, `--adapter-recipe`, and `--require-recipes`, and the resulting recipe-slot adapter passed `migration.adapter_validate`.

This does not make the MAC lifecycle sprint fully A-path compliant yet. The verified GLM adapter has not been carried through the remaining standard recipe runbook steps: `template_maker.cross_generator_from_adapters`, `template_maker.render_cases`, `runner.compile_run`, `runner.analyze_results`, and `runner.analyze_cross_results` in the standard verification artifact layout.

## Environment

- `ZHIPUAI_API_KEY present`: `true`
- `GLM_API_KEY present`: `true`
- key contents printed: `false`
- key contents stored in artifacts: `false`

The first sandboxed execution attempt failed with an outbound connection denial. The network-enabled rerun completed successfully.

## Adapter Output

- adapter: `artifacts/sprints/mac_lifecycle_family_v1/llm_slot_filling_verification/adapters_recipe_llm/MAC_LIFECYCLE_V1_SOURCE_TEMPLATE/openssl_mbedtls_mac_lifecycle/adapter.yaml`
- validated adapter: `artifacts/sprints/mac_lifecycle_family_v1/llm_slot_filling_verification/adapters_recipe_llm_validated/MAC_LIFECYCLE_V1_SOURCE_TEMPLATE/openssl_mbedtls_mac_lifecycle/adapter.yaml`
- `_ignored_disallowed_fields`: `[]`
- `_ignored_non_slot_fields`: `[]`
- disallowed free-form blocks found: `false`
- manual/fallback/missing/api-error markers found: `false`

## Slot Bindings

| slot | value |
| --- | --- |
| `openssl_MAC_FETCH_API` | `EVP_MAC_fetch` |
| `openssl_MAC_CTX_NEW_API` | `EVP_MAC_CTX_new` |
| `openssl_MAC_INIT_API` | `EVP_MAC_init` |
| `openssl_MAC_UPDATE_API` | `EVP_MAC_update` |
| `openssl_MAC_FINAL_API` | `EVP_MAC_final` |
| `openssl_MAC_FREE_API` | `EVP_MAC_CTX_free` |
| `openssl_MAC_ALGORITHM` | `CMAC` |
| `mbedtls_psa_MAC_SETUP_API` | `psa_mac_sign_setup` |
| `mbedtls_psa_MAC_UPDATE_API` | `psa_mac_update` |
| `mbedtls_psa_MAC_FINAL_API` | `psa_mac_sign_finish` |
| `mbedtls_psa_MAC_ABORT_API` | `psa_mac_abort` |
| `mbedtls_psa_MAC_ALGORITHM` | `PSA_ALG_CMAC` |

## Validation

- `adapter_validate_executed`: `true`
- `status`: `ok`
- `needs_repair`: `0`
- `errors`: `[]`
- `warnings`: `selected_mask_units loaded as trace context for recipe adapter`

## Interpretation

The GLM adapter preserves the intended MAC lifecycle vulnerability path: repeated finalization and update-after-final state transitions are represented through OpenSSL `EVP_MAC_*` and mbedTLS PSA MAC APIs. No free-form C blocks were accepted from the LLM output.
