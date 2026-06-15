# nullderef_null_mac_ctx_init_triage_v1 Report

## Summary

- family: null_deref_dispatch
- case_id: nullderef_null_mac_ctx_init
- original_label: sanitizer_candidate
- decision: downgrade_to_contract_observation
- quality_status: pass_downgraded_contract_observation

## Reproduction

- candidate_reproduced: true
- candidate_reproduced_in_minimal_harness: true
- ubsan_location: openssl_internal
- top relevant frame: EVP_MAC_init ../openssl-3.5.5-asan-src/crypto/evp/mac_lib.c:118

## Contract Interpretation

`EVP_MAC_init(NULL, ...)` is outside the documented context lifecycle. Valid context controls did not produce sanitizer evidence. Therefore this should be retained as a hardening observation, not a default promoted sanitizer candidate.

## Safety Notes

No public target was accessed. No exploit chain was generated. No confirmed vulnerability, CVE, or exploitability claim is made.
