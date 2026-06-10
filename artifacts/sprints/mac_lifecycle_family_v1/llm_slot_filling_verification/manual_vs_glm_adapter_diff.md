# Manual Adapter vs GLM Adapter

## Paths

- manual adapter: `artifacts/sprints/mac_lifecycle_family_v1/recipe/adapter.yaml`
- GLM adapter: `artifacts/sprints/mac_lifecycle_family_v1/llm_slot_filling_verification/adapters_recipe_llm/MAC_LIFECYCLE_V1_SOURCE_TEMPLATE/openssl_mbedtls_mac_lifecycle/adapter.yaml`
- validated GLM adapter: `artifacts/sprints/mac_lifecycle_family_v1/llm_slot_filling_verification/adapters_recipe_llm_validated/MAC_LIFECYCLE_V1_SOURCE_TEMPLATE/openssl_mbedtls_mac_lifecycle/adapter.yaml`

## Status Comparison

| field | manual adapter | GLM adapter |
| --- | --- | --- |
| `_adapter_mode` | `recipe_slot_filling` | `recipe_slot_filling` |
| `_llm_status` | `manual_controlled_slot_binding` | `ok` |
| `validation.status` | available in `recipe_validated/adapter.yaml` | `ok` |
| disallowed free-form fields | `false` | `false` |
| manual/fallback marker | `manual_controlled_slot_binding` | `false` |

## Slot Binding Comparison

The manual and GLM adapters have identical `slot_bindings`:

| slot | manual value | GLM value |
| --- | --- | --- |
| `openssl_MAC_FETCH_API` | `EVP_MAC_fetch` | `EVP_MAC_fetch` |
| `openssl_MAC_CTX_NEW_API` | `EVP_MAC_CTX_new` | `EVP_MAC_CTX_new` |
| `openssl_MAC_INIT_API` | `EVP_MAC_init` | `EVP_MAC_init` |
| `openssl_MAC_UPDATE_API` | `EVP_MAC_update` | `EVP_MAC_update` |
| `openssl_MAC_FINAL_API` | `EVP_MAC_final` | `EVP_MAC_final` |
| `openssl_MAC_FREE_API` | `EVP_MAC_CTX_free` | `EVP_MAC_CTX_free` |
| `openssl_MAC_ALGORITHM` | `CMAC` | `CMAC` |
| `mbedtls_psa_MAC_SETUP_API` | `psa_mac_sign_setup` | `psa_mac_sign_setup` |
| `mbedtls_psa_MAC_UPDATE_API` | `psa_mac_update` | `psa_mac_update` |
| `mbedtls_psa_MAC_FINAL_API` | `psa_mac_sign_finish` | `psa_mac_sign_finish` |
| `mbedtls_psa_MAC_ABORT_API` | `psa_mac_abort` | `psa_mac_abort` |
| `mbedtls_psa_MAC_ALGORITHM` | `PSA_ALG_CMAC` | `PSA_ALG_CMAC` |

## Findings

- The GLM adapter did not introduce `init_block`, `input_construction_block`, `trigger_block`, `cleanup_block`, or `oracle_strategy`.
- The GLM adapter did not introduce bignum, DER, or X.509 family residue.
- The GLM adapter preserves the same vulnerability path as the manual adapter: MAC lifecycle state transitions after terminal finalization, including repeated final and update-after-final observability.
- The GLM adapter passed `migration.adapter_validate` with `status: ok` and `needs_repair: 0`.

## Conclusion

GLM/LLM slot-filling is verified for the MAC lifecycle A-path adapter step. This replaces the earlier manual-only evidence for `llm_slot_bindings_only`, but it does not by itself establish full A-path compliance because the verified GLM adapter has not yet been run through the full standard cross-template, render, compile, and generic analysis chain.
