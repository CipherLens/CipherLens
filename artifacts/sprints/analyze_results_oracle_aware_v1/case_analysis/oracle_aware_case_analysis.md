# Oracle-Aware Case Analysis

- total_cases: 14
- normal_reject_observed: 14
- normal_accept_observed: 0
- full_consumption_gap_candidate: 0
- oracle_event_incomplete: 0

## pkcs_container_parsing_openssl__mut_001__seed_preserving_baseline
- family: pkcs_container_parsing
- mutation_strategy: seed_preserving_baseline
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_002__trailing_garbage
- family: pkcs_container_parsing
- mutation_strategy: trailing_garbage
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_003__malformed_length
- family: pkcs_container_parsing
- mutation_strategy: malformed_length
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_004__nested_length_mismatch
- family: pkcs_container_parsing
- mutation_strategy: nested_length_mismatch
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_005__invalid_container_structure
- family: pkcs_container_parsing
- mutation_strategy: invalid_container_structure
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_006__pem_der_format_toggle
- family: pkcs_container_parsing
- mutation_strategy: pem_der_format_toggle
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## pkcs_container_parsing_openssl__mut_007__expected_return_flip
- family: pkcs_container_parsing
- mutation_strategy: expected_return_flip
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_001__seed_preserving_baseline
- family: asn1_nested_boundary
- mutation_strategy: seed_preserving_baseline
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_002__trailing_garbage
- family: asn1_nested_boundary
- mutation_strategy: trailing_garbage
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_003__short_length
- family: asn1_nested_boundary
- mutation_strategy: short_length
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_004__long_length
- family: asn1_nested_boundary
- mutation_strategy: long_length
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_005__nested_length_mismatch
- family: asn1_nested_boundary
- mutation_strategy: nested_length_mismatch
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_006__nested_depth_variation
- family: asn1_nested_boundary
- mutation_strategy: nested_depth_variation
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself

## asn1_nested_boundary_openssl__mut_007__expected_return_flip
- family: asn1_nested_boundary
- mutation_strategy: expected_return_flip
- semantic_observation: normal_reject_observed
- candidate_label: normal_reject
- reason: accepted=false path observed; full_consumption=false on reject path is not a gap by itself
