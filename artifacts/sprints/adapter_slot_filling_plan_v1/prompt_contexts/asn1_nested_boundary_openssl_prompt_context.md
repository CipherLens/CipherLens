# Slot filling prompt context: asn1_nested_boundary.openssl.family_adapter_recipe_v1

- adapter_id: `asn1_nested_boundary.openssl.family_adapter_recipe_v1`
- family: `asn1_nested_boundary`
- target_library: `openssl`
- source template: `artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary/canonical_tmpl_wolfssl.c`
- selected_mask_units: `artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary/selected_mask_units.yaml`

## Selected Mask Units
- ASTLITE-0005: role=trigger_call, suggested_use=migrate_api_call, placeholder=
- ASTLITE-0004: role=trigger_call, suggested_use=migrate_api_call, placeholder=
- ASTLITE-0007: role=trigger_call, suggested_use=migrate_api_call, placeholder=
- ASTLITE-0009: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[EXPECT_RET]
- ASTLITE-0011: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[EXPECT_RET]
- ASTLITE-0001: role=mutation_point, suggested_use=llm_reconstruction_context, placeholder=[DER_BYTES]
- ASTLITE-0010: role=helper_function, suggested_use=preserve_input_preparation, placeholder=
- ASTLITE-0018: role=cleanup, suggested_use=preserve_cleanup, placeholder=[EXPECT_RET]
- ASTLITE-0017: role=helper_function, suggested_use=preserve_input_preparation, placeholder=
- ASTLITE-0002: role=entrypoint, suggested_use=llm_reconstruction_context, placeholder=[DER_LENGTH]
- ASTLITE-0014: role=cleanup, suggested_use=preserve_cleanup, placeholder=

## Allowed Target APIs
- `ASN1_item_d2i`

## Forbidden Target APIs
- `d2i_X509`

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
- `needs_manual_review_wc_ParseCert`

## Output Contract
- 输出必须是 YAML `slot_bindings` 结构。
- 禁止生成 C。
- 禁止绕过 mapping gate。
- 禁止声称 confirmed equivalence。
- 禁止使用 blocked/no_direct_counterpart target。
- 本文件只是 prompt context；本 sprint 不调用 GLM。
