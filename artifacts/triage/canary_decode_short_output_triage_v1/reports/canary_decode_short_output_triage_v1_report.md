# canary_decode_short_output_triage_v1 Report

## Summary

- family: buffer_canary_boundary
- case_id: canary_decode_short_output
- trigger_api: EVP_DecodeBlock
- original_label: sanitizer_candidate
- decision: downgrade_to_contract_observation
- asan_location: openssl_internal
- exact_output_control_passed: True
- short_output_only_failure: True

## Variant Results

- decode_valid_exact_output_buffer: label=no_candidate asan=False canary=False contract=False crash=none
- decode_valid_one_byte_short_output_buffer: label=contract_boundary_observation asan=False canary=True contract=True crash=none
- decode_valid_zero_output_buffer_disabled_or_guarded: label=no_candidate asan=False canary=False contract=True crash=none
- decode_malformed_exact_output_buffer: label=no_candidate asan=False canary=False contract=False crash=none
- decode_malformed_short_output_buffer: label=no_candidate asan=False canary=False contract=True crash=none
- decode_padding_edge_short_output_buffer: label=contract_boundary_observation asan=False canary=True contract=True crash=none
- original_input_len_mismatch: label=contract_boundary_observation asan=True canary=True contract=True crash=SIGABRT

## Contract Interpretation

EVP_DecodeBlock produces exactly 3 output bytes for every 4 input bytes and has no output buffer size parameter; caller must provide enough t capacity. Short output buffers are invalid API use. The original ASAN is also tied to an overclaimed input length.

## Policy Notes

No public target access, exploit chain, main feedback write, pattern bank modification, git operation, DER trailing-garbage replay, full-consumption oracle, or confirmed vulnerability claim was used.
