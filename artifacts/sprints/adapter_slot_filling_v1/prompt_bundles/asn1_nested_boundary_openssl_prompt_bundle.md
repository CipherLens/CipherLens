# Adapter Slot Filling Prompt Bundle

adapter_id: `asn1_nested_boundary.openssl.family_adapter_recipe_v1`

Generate YAML only for `adapter_slot_bindings_v1`.

Hard rules:
- Do not generate C code, C snippets, harnesses, compiler commands, or renderable templates.
- Fill `slot_bindings` only; do not alter `adapter_recipe.yaml`.
- Use only target APIs allowed by the slot plan and validation rules.
- Do not use blocked or forbidden target APIs.
- Do not claim confirmed equivalence; candidate mappings must remain candidate-only.
- Preserve cleanup, oracle, input, and mutation-slot mappings as structured YAML.

Expected top-level YAML fields:
`adapter_id`, `family`, `source_library`, `target_library`, `binding_status`,
`mapping_gate`, `api_mapping`, `type_mapping`, `cleanup_mapping`,
`oracle_mapping`, `input_mapping`, `mutation_slot_mapping`,
`validation_notes`, `risk_notes`.

## Slot Filling Plan
```yaml
schema: adapter_slot_filling_plan_v1
adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
family: asn1_nested_boundary
source_library: wolfssl
target_library: openssl
template_level: family
source_template:
  family_template_dir: artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary
  canonical_template: artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary/canonical_tmpl_wolfssl.c
  selected_mask_units: artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary/selected_mask_units.yaml
adapter_recipe:
  path: adapter_recipes/wolfssl_family/asn1_nested_boundary/openssl/adapter_recipe.yaml
  required_bindings:
  - api_mapping
  - type_mapping
  - cleanup_mapping
  - oracle_mapping
  - input_mapping
  - mutation_slot_mapping
slot_groups:
  api_mapping:
    required: true
    source_slots:
    - wc_InitDecodedCert
    - wc_ParseCert
    - wc_FreeDecodedCert
    - ASN1_item_d2i
    - mbedtls_x509_crt_parse_der
    allowed_target_apis:
    - ASN1_item_d2i
    forbidden_target_apis:
    - d2i_X509
  type_mapping:
    required: true
    source_types:
    - family_source_types_from_template
    target_type_candidates:
    - to_be_filled_as_slot_bindings
  cleanup_mapping:
    required: true
    source_cleanup_slots:
    - slot_name: cleanup_call
      source_cleanup: family-specific wolfSSL cleanup/free API
      target_cleanup_candidates: []
      required: true
    target_cleanup_candidates:
    - to_be_filled_as_slot_bindings
  oracle_mapping:
    required: true
    source_oracles:
    - parser_reject_accept
    target_oracle_candidates:
    - return_code
    - output_state
    - parser_result
    - sanitizer_signal
  input_mapping:
    required: true
    input_slots:
    - ASN1_NESTED_LENGTH
    - DER_BYTES
    - DER_LENGTH
    - EXPECT_RET
    - NESTED_DEPTH
    - TRAILING_GARBAGE
    preservation_requirements:
    - preserve family-level vulnerability path
    - preserve input length/buffer pairing
    - do not introduce blocked target API
  mutation_slot_mapping:
    required: true
    mutation_slots:
    - ASN1_NESTED_LENGTH
    - DER_BYTES
    - TRAILING_GARBAGE
    - NESTED_DEPTH
    - EXPECT_RET
    allowed_mutation_policy: bind existing family mutation slots only
glm_policy:
  allowed_now: false
  allowed_later_for:
  - adapter_slot_filling
  forbidden:
  - full_c_generation
  - freeform_harness_generation
  - bypass_mapping_gate
validation_before_render:
- all_required_bindings_present
- no_forbidden_target_api
- cleanup_mapping_present
- oracle_mapping_present
- no_confirmed_equivalence_claim
- blocked_targets_respected
selected_mask_units_summary:
- unit_id: ASTLITE-0005
  role: trigger_call
  suggested_use: migrate_api_call
  placeholder: ''
  function: ''
- unit_id: ASTLITE-0004
  role: trigger_call
  suggested_use: migrate_api_call
  placeholder: ''
  function: wc_InitDecodedCert
- unit_id: ASTLITE-0007
  role: trigger_call
  suggested_use: migrate_api_call
  placeholder: ''
  function: ''
- unit_id: ASTLITE-0009
  role: mutation_point
  suggested_use: llm_reconstruction_context
  placeholder: '[EXPECT_RET]'
  function: ''
- unit_id: ASTLITE-0011
  role: mutation_point
  suggested_use: llm_reconstruction_context
  placeholder: '[EXPECT_RET]'
  function: ''
- unit_id: ASTLITE-0001
  role: mutation_point
  suggested_use: llm_reconstruction_context
  placeholder: '[DER_BYTES]'
  function: ''
- unit_id: ASTLITE-0010
  role: helper_function
  suggested_use: preserve_input_preparation
  placeholder: ''
  function: wolfSSL_X509_d2i
- unit_id: ASTLITE-0018
  role: cleanup
  suggested_use: preserve_cleanup
  placeholder: '[EXPECT_RET]'
  function: ''
- unit_id: ASTLITE-0017
  role: helper_function
  suggested_use: preserve_input_preparation
  placeholder: ''
  function: wolfSSL_i2d_X509_bio
- unit_id: ASTLITE-0002
  role: entrypoint
  suggested_use: llm_reconstruction_context
  placeholder: '[DER_LENGTH]'
  function: main
- unit_id: ASTLITE-0014
  role: cleanup
  suggested_use: preserve_cleanup
  placeholder: ''
  function: ''
notes:
- Plan only. No GLM call in this sprint.
- GLM output must be YAML slot_bindings only.
- Candidate mapping must remain candidate, not confirmed equivalence.

```

## Slot Bindings Schema
```yaml
schema: slot_bindings_schema_v1
adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
family: asn1_nested_boundary
target_library: openssl
required_top_level_fields:
- adapter_id
- family
- source_library
- target_library
- api_mapping
- type_mapping
- cleanup_mapping
- oracle_mapping
- input_mapping
- mutation_slot_mapping
- validation_notes
- risk_notes
field_constraints:
  api_mapping:
    must_use_allowed_target_apis: true
    must_not_use_forbidden_target_apis: true
  cleanup_mapping:
    required: true
  oracle_mapping:
    required: true
  mutation_slot_mapping:
    must_preserve_family_mutation_policy: true
  validation_notes:
    must_include_no_confirmed_equivalence_claim: true

```

## Adapter Recipe
```yaml
schema: family_adapter_recipe_v1
adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
family: asn1_nested_boundary
source_library: wolfssl
target_library: openssl
template_level: family
source_template:
  family_template_dir: artifacts/sprints/family_template_generalization_v1/family_packages/asn1_nested_boundary
  canonical_template: canonical_tmpl_wolfssl.c
  family_template_meta: family_template_meta.yaml
  selected_mask_units: selected_mask_units.yaml
source_slots:
  api_slots:
  - slot_name: wc_InitDecodedCert
    source_api: wc_InitDecodedCert
    allowed_target_apis:
    - mbedtls:mbedtls_x509_crt_parse_der
    - openssl:ASN1_item_d2i
    blocked_target_apis: []
    mapping_gate_status:
    - usable_for_adapter
    notes: candidate mapping only; not confirmed equivalence
  - slot_name: wc_ParseCert
    source_api: wc_ParseCert
    allowed_target_apis: []
    blocked_target_apis:
    - mbedtls:mbedtls_x509_crt_parse_der
    - openssl:d2i_X509
    mapping_gate_status:
    - needs_manual_review
    notes: candidate mapping only; not confirmed equivalence
  - slot_name: wc_FreeDecodedCert
    source_api: wc_FreeDecodedCert
    allowed_target_apis: []
    blocked_target_apis: []
    mapping_gate_status:
    - not_in_mapping_gate
    notes: candidate mapping only; not confirmed equivalence
  - slot_name: ASN1_item_d2i
    source_api: ''
    allowed_target_apis:
    - openssl:ASN1_item_d2i
    blocked_target_apis: []
    mapping_gate_status:
    - usable_for_adapter
    notes: candidate mapping only; not confirmed equivalence
  - slot_name: mbedtls_x509_crt_parse_der
    source_api: ''
    allowed_target_apis:
    - mbedtls:mbedtls_x509_crt_parse_der
    blocked_target_apis:
    - mbedtls:mbedtls_x509_crt_parse_der
    mapping_gate_status:
    - needs_manual_review
    - usable_for_adapter
    notes: candidate mapping only; not confirmed equivalence
  mutation_slots:
  - ASN1_NESTED_LENGTH
  - DER_BYTES
  - TRAILING_GARBAGE
  - NESTED_DEPTH
  - EXPECT_RET
  cleanup_slots:
  - slot_name: cleanup_call
    source_cleanup: family-specific wolfSSL cleanup/free API
    target_cleanup_candidates: []
    required: true
  oracle_slots:
  - parser_reject_accept
target_mapping:
  mapping_gate_status:
  - adapter_ready
  - needs_manual_review
  target_apis:
  - ASN1_item_d2i
  candidate_only_apis:
  - ASN1_item_d2i
  blocked_apis:
  - d2i_X509
  mappings:
  - family: asn1_nested_boundary
    source_library: wolfssl
    target_library: openssl
    wolfssl_api: wc_InitDecodedCert
    target_api: ASN1_item_d2i
    mapping_type: semantic_related
    required_oracle_style: parser_reject_accept
    adapter_slot_hint: DER input, length, parser result slots
    cleanup_mapping_hint: family-specific cleanup if object allocated
    lifecycle_hint: candidate lifecycle must be verified by generated harness
    risk_notes: candidate mapping only; compile/run/analyze still required
  blocked_mappings:
  - family: asn1_nested_boundary
    wolfssl_api: wc_ParseCert
    target_library: openssl
    target_api: d2i_X509
    reason: needs_manual_review
    recommendation: manual_review_before_adapter
    notes: not adapter-ready under current evidence gate
  confirmed_equivalence: false
slot_binding_policy:
  glm_allowed: false
  glm_allowed_later_for:
  - adapter_slot_filling
  required_bindings:
  - api_mapping
  - type_mapping
  - cleanup_mapping
  - oracle_mapping
  - input_mapping
  - mutation_slot_mapping
validation:
  require_trigger_call: true
  require_cleanup_call: true
  require_oracle_check: true
  require_blocked_targets_respected: true
  require_no_confirmed_equivalence_claim: true
oracle_strategy:
  primary:
  - parser_reject_accept
  secondary: []
false_positive_risks:
- api_misuse
- candidate_mapping_not_confirmed
- no_direct_counterpart
- needs_manual_review_wc_ParseCert
render_policy:
  render_allowed_now: false
  render_allowed_after:
  - adapter_slot_filling
  - adapter_validate
compile_policy:
  compile_allowed_now: false
selected_mask_units_used:
- unit_id: ASTLITE-0005
  role: trigger_call
  suggested_use: migrate_api_call
- unit_id: ASTLITE-0004
  role: trigger_call
  suggested_use: migrate_api_call
- unit_id: ASTLITE-0007
  role: trigger_call
  suggested_use: migrate_api_call
- unit_id: ASTLITE-0009
  role: mutation_point
  suggested_use: llm_reconstruction_context
- unit_id: ASTLITE-0011
  role: mutation_point
  suggested_use: llm_reconstruction_context
- unit_id: ASTLITE-0001
  role: mutation_point
  suggested_use: llm_reconstruction_context
- unit_id: ASTLITE-0010
  role: helper_function
  suggested_use: preserve_input_preparation
- unit_id: ASTLITE-0018
  role: cleanup
  suggested_use: preserve_cleanup
- unit_id: ASTLITE-0017
  role: helper_function
  suggested_use: preserve_input_preparation
- unit_id: ASTLITE-0002
  role: entrypoint
  suggested_use: llm_reconstruction_context
- unit_id: ASTLITE-0014
  role: cleanup
  suggested_use: preserve_cleanup
notes:
- Family-level adapter recipe skeleton only.
- Candidate mapping is not confirmed API equivalence.
- No GLM, render, compile, run, or C generation in this sprint.

```

## Prompt Context
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


## Validation Rules
```yaml
schema: adapter_slot_binding_validation_rules_v1
global_rules:
- no_full_c_generation
- no_blocked_target_api
- no_confirmed_equivalence_claim
- all_required_bindings_present
- cleanup_mapping_required
- oracle_mapping_required
- mapping_gate_status_recorded
- candidate_mapping_must_remain_candidate
adapter_specific_rules:
- adapter_id: asn1_nested_boundary.mbedtls.family_adapter_recipe_v1
  required_bindings:
  - api_mapping
  - type_mapping
  - cleanup_mapping
  - oracle_mapping
  - input_mapping
  - mutation_slot_mapping
  forbidden_target_apis:
  - mbedtls_x509_crt_parse_der
  allowed_target_apis:
  - mbedtls_x509_crt_parse_der
  required_oracles:
  - parser_reject_accept
  required_cleanup:
  - slot_name: cleanup_call
    source_cleanup: family-specific wolfSSL cleanup/free API
    target_cleanup_candidates: []
    required: true
- adapter_id: asn1_nested_boundary.openssl.family_adapter_recipe_v1
  required_bindings:
  - api_mapping
  - type_mapping
  - cleanup_mapping
  - oracle_mapping
  - input_mapping
  - mutation_slot_mapping
  forbidden_target_apis:
  - d2i_X509
  allowed_target_apis:
  - ASN1_item_d2i
  required_oracles:
  - parser_reject_accept
  required_cleanup:
  - slot_name: cleanup_call
    source_cleanup: family-specific wolfSSL cleanup/free API
    target_cleanup_candidates: []
    required: true
- adapter_id: pkcs_container_parsing.openssl.family_adapter_recipe_v1
  required_bindings:
  - api_mapping
  - type_mapping
  - cleanup_mapping
  - oracle_mapping
  - input_mapping
  - mutation_slot_mapping
  forbidden_target_apis:
  - d2i_PKCS7
  allowed_target_apis:
  - PKCS12_parse
  - PKCS7_verify
  required_oracles:
  - parser_reject_accept
  required_cleanup:
  - slot_name: cleanup_call
    source_cleanup: family-specific wolfSSL cleanup/free API
    target_cleanup_candidates: []
    required: true

```

## Blocked Targets
```yaml
schema: blocked_slot_filling_targets_v1
blocked_targets:
- family: pkcs_container_parsing
  target_library: mbedtls
  blocked_reason: no_direct_counterpart
  blocked_apis:
  - wc_PKCS12_parse
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - do_not_generate_adapter
  - requires_new_target_strategy
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: pkcs_container_parsing
  target_library: mbedtls
  blocked_reason: no_direct_counterpart
  blocked_apis:
  - wc_PKCS7_DecodeSignedData
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - do_not_generate_adapter
  - requires_new_target_strategy
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: pkcs_container_parsing
  target_library: openssl
  blocked_reason: weak_evidence
  blocked_apis:
  - d2i_PKCS7
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - do_not_generate_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: pkcs_container_parsing
  target_library: mbedtls
  blocked_reason: no_direct_counterpart
  blocked_apis:
  - wc_PKCS7_VerifySignedData
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - do_not_generate_adapter
  - requires_new_target_strategy
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: asn1_nested_boundary
  target_library: mbedtls
  blocked_reason: needs_manual_review
  blocked_apis:
  - mbedtls_x509_crt_parse_der
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - manual_review_before_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: asn1_nested_boundary
  target_library: openssl
  blocked_reason: needs_manual_review
  blocked_apis:
  - d2i_X509
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - manual_review_before_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.
- family: x509_parsing
  target_library: mbedtls
  blocked_reason: needs_manual_review
  blocked_apis:
  - mbedtls_x509_crt_parse_der
  why_not_slot_filling: blocked/no_direct/weak/manual-review target must not enter
    slot filling
  recommendation:
  - manual_review_before_adapter
  - manual_review_before_adapter
  notes:
  - not adapter-ready under current evidence gate
  - candidate_only mappings are not confirmed equivalence.

```
