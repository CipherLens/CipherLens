# Slot filling prompt context: pkcs_container_parsing.openssl.family_adapter_recipe_v1

- adapter_id: `pkcs_container_parsing.openssl.family_adapter_recipe_v1`
- family: `pkcs_container_parsing`
- target_library: `openssl`
- source template: `artifacts/sprints/family_template_generalization_v1/family_packages/pkcs_container_parsing/canonical_tmpl_wolfssl.c`
- selected_mask_units: `artifacts/sprints/family_template_generalization_v1/family_packages/pkcs_container_parsing/selected_mask_units.yaml`

## Selected Mask Units
- ASTLITE-0003: role=mutation_point, suggested_use=mutate_value, placeholder=[ATTRIBUTE_COUNT]
- ASTLITE-0004: role=mutation_point, suggested_use=mutate_value, placeholder=[ATTRIBUTE_COUNT]
- ASTLITE-0001: role=mutation_point, suggested_use=mutate_value, placeholder=[CONTAINER_OPERATION]
- ASTLITE-0002: role=mutation_point, suggested_use=mutate_value, placeholder=[CONTAINER_OPERATION]
- ASTLITE-0015: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[EXPECT_RET]
- ASTLITE-0033: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[EXPECT_RET]
- ASTLITE-0026: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[0]
- ASTLITE-0027: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[0]
- ASTLITE-0028: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[0]
- ASTLITE-0029: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[0]
- ASTLITE-0030: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[0]
- ASTLITE-0007: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[256]

## Allowed Target APIs
- `PKCS12_parse`
- `PKCS7_verify`

## Forbidden Target APIs
- `d2i_PKCS7`

## Required Bindings
- `api_mapping`
- `type_mapping`
- `cleanup_mapping`
- `oracle_mapping`
- `input_mapping`
- `mutation_slot_mapping`

## Oracle Strategy
- primary/secondary: `{'primary': ['parser_reject_accept'], 'secondary': []}`

## Cleanup Requirements
- cleanup slots: `[{'slot_name': 'cleanup_call', 'source_cleanup': 'family-specific wolfSSL cleanup/free API', 'target_cleanup_candidates': [], 'required': True}]`

## False Positive Risks
- `api_misuse`
- `candidate_mapping_not_confirmed`
- `no_direct_counterpart`

## Output Contract
- 输出必须是 YAML `slot_bindings` 结构。
- 禁止生成 C。
- 禁止绕过 mapping gate。
- 禁止声称 confirmed equivalence。
- 禁止使用 blocked/no_direct_counterpart target。
- 本文件只是 prompt context；本 sprint 不调用 GLM。
