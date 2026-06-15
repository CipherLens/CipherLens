# memlen_null_input_nonzero_triage_v1 Report

## Summary

- family: memory_length_boundary
- case_id: memlen_null_input_nonzero
- trigger_api: EVP_EncodeBlock
- original_label: sanitizer_candidate
- decision: downgrade_to_contract_observation
- ubsan_location: openssl_internal
- candidate_reproduced: True

## Variant Results

- null_input_zero_len: label=no_candidate asan=False ubsan=False crash=none
- null_input_nonzero_len_original: label=sanitizer_candidate asan=False ubsan=True crash=none
- valid_input_same_nonzero_len: label=no_candidate asan=False ubsan=False crash=none
- short_input_claimed_larger_len: label=sanitizer_candidate asan=True ubsan=False crash=SIGABRT
- null_output_zero_len_boundary: label=sanitizer_candidate asan=False ubsan=True crash=none

## Contract Interpretation

EVP_EncodeBlock expects f to point to input data of length n; NULL f with n > 0 is invalid API use. NULL f with n == 0 did not trigger sanitizer locally but is not explicitly documented as allowed.

## Policy Notes

No public target access, exploit chain, main feedback write, pattern bank modification, git operation, DER trailing-garbage replay, full-consumption oracle, or confirmed vulnerability claim was used.
