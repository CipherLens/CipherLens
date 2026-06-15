Output YAML only. No explanation. No markdown. No ``` fences.
Do not repeat the slot_filling_plan. Do not generate C. Do not generate a harness.

Task: fill ONLY pkcs_container_parsing -> OpenSSL slot_bindings.

Allowed trigger target APIs:
- PKCS12_parse
- PKCS7_verify

Allowed cleanup target APIs:
- PKCS12_free
- PKCS7_free

Forbidden:
- d2i_PKCS7
- any mbedTLS API
- confirmed_equivalence: true
- any C code, #include, int main, function body, compiler command

Required YAML shape:
schema: adapter_slot_bindings_v1
adapter_id: pkcs_container_parsing_openssl
family: pkcs_container_parsing
source_library: wolfssl
target_library: openssl
binding_status: filled_by_glm
api_mapping:
  - source_slot: wc_PKCS12_parse
    source_api: wc_PKCS12_parse
    target_api: PKCS12_parse
    mapping_gate_status: usable_for_adapter
    confirmed_equivalence: false
    notes: candidate mapping only
  - source_slot: wc_PKCS7_VerifySignedData
    source_api: wc_PKCS7_VerifySignedData
    target_api: PKCS7_verify
    mapping_gate_status: usable_for_adapter
    confirmed_equivalence: false
    notes: candidate mapping only
type_mapping: []
cleanup_mapping:
  - target_api: PKCS12_free
    applies_to: PKCS12 object if allocated
    required: true
  - target_api: PKCS7_free
    applies_to: PKCS7 object if allocated
    required: true
oracle_mapping:
  primary: parser_reject_accept
  secondary:
    - return_code_semantics
  target_observables:
    - return_code
    - parser_result
    - output_state
  notes: candidate oracle only; no vulnerability claim
input_mapping:
  input_slots: []
  preservation_requirements:
    - preserve family-level vulnerability path
    - preserve input length/buffer pairing
    - do not introduce blocked target API
  notes: bind only existing family input slots
mutation_slot_mapping: []
validation_notes:
  no_confirmed_equivalence_claim: true
  blocked_targets_respected: true
  no_c_generation: true
  cleanup_mapping_present: true
  oracle_mapping_present: true
risk_notes:
  - candidate mapping only; adapter_validate/render/compile not run

Fill input_mapping.input_slots using exactly these slots:
- '0'
- '256'
- '4096'
- ATTRIBUTE_COUNT
- ATTRIBUTE_OID_BYTES
- ATTRIBUTE_VALUE_BYTES
- CONTAINER_BYTES
- CONTAINER_FORMAT
- CONTAINER_OPERATION
- EXPECT_RET
- FAMILY_ATTRIBUTE_COUNT
- NESTED_LENGTH_DELTA
- TRAILING_BYTES


Fill mutation_slot_mapping using exactly these mutation slots:
- CONTAINER_BYTES
- CONTAINER_FORMAT
- TRAILING_BYTES
- NESTED_LENGTH_DELTA
- EXPECT_RET


Minimal context:
adapter_recipe.target_mapping:
mapping_gate_status:
- adapter_ready
- weak_evidence
target_apis:
- PKCS12_parse
- PKCS7_verify
candidate_only_apis:
- PKCS12_parse
- PKCS7_verify
blocked_apis:
- d2i_PKCS7
mappings:
- family: pkcs_container_parsing
  source_library: wolfssl
  target_library: openssl
  wolfssl_api: wc_PKCS12_parse
  target_api: PKCS12_parse
  mapping_type: parser_equivalent
  required_oracle_style: parser_reject_accept
  adapter_slot_hint: container input, parser/verify, cleanup slots
  cleanup_mapping_hint: family-specific cleanup if object allocated
  lifecycle_hint: candidate lifecycle must be verified by generated harness
  risk_notes: candidate mapping only; compile/run/analyze still required
- family: pkcs_container_parsing
  source_library: wolfssl
  target_library: openssl
  wolfssl_api: wc_PKCS7_VerifySignedData
  target_api: PKCS7_verify
  mapping_type: parser_equivalent
  required_oracle_style: parser_reject_accept
  adapter_slot_hint: container input, parser/verify, cleanup slots
  cleanup_mapping_hint: family-specific cleanup if object allocated
  lifecycle_hint: candidate lifecycle must be verified by generated harness
  risk_notes: candidate mapping only; compile/run/analyze still required
blocked_mappings:
- family: pkcs_container_parsing
  wolfssl_api: wc_PKCS7_DecodeSignedData
  target_library: openssl
  target_api: d2i_PKCS7
  reason: weak_evidence
  recommendation: manual_review_before_adapter
  notes: not adapter-ready under current evidence gate
confirmed_equivalence: false


family mutation slots:
- slot_name: CONTAINER_BYTES
  slot_type: byte_array
  examples:
  - valid_pkcs12_der
  - malformed_pkcs7_der
  allowed_mutations:
  - boundary
  - malformed
  - valid_control
  safety_notes: container data must remain bounded
- slot_name: CONTAINER_FORMAT
  slot_type: enum
  examples:
  - DER
  - PEM
  allowed_mutations:
  - boundary
  - malformed
  - valid_control
  safety_notes: avoid format/API mismatch false positives
- slot_name: TRAILING_BYTES
  slot_type: byte_array
  examples:
  - empty
  - '00'
  - ff00
  allowed_mutations:
  - boundary
  - malformed
  - valid_control
  safety_notes: only meaningful for APIs exposing consumption
- slot_name: NESTED_LENGTH_DELTA
  slot_type: integer
  examples:
  - '-1'
  - '0'
  - '+1'
  - large
  allowed_mutations:
  - boundary
  - malformed
  - valid_control
  safety_notes: nested length mutation can become generic parse failure
- slot_name: EXPECT_RET
  slot_type: enum
  examples:
  - success
  - reject
  allowed_mutations:
  - boundary
  - malformed
  - valid_control
  safety_notes: do not hard-code library numeric values


family oracle plan:
schema: family_oracle_plan_v1
family: pkcs_container_parsing
template_level: family
oracle_types:
- parser_reject_accept
- return_code_semantics
- full_consumption
- cleanup_required
safe_behavior: safe reject, bounded return state, or no sanitizer evidence depending
  on family oracle
bug_behavior: matches migrated family oracle; requires explicit evidence
triage_behavior: oracle signal insufficient or candidate mapping weakened
no_vulnerability_claim: true

