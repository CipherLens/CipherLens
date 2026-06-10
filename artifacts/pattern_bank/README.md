# Historical Pattern Bank Summary

This run scanned `data/pocs/core10/` and `datasets/openssl/poc_artifacts/`.

- core10 patterns: 10
- OpenSSL issue artifact patterns: 30
- unified patterns: 42
- family distribution: {'memory_length_boundary': 2, 'bn_mpi_arithmetic': 1, 'pkey_verify_semantic': 11, 'cipher_aead_lifecycle': 4, 'api_state_machine': 4, 'asn1_nested_boundary': 7, 'der_full_consumption': 1, 'x509_parsing': 11, 'mac_lifecycle': 1}
- oracle_type distribution: {'crash_or_sanitizer': 19, 'projection_limitation': 1, 'behavior_divergence': 14, 'safe_reject_baseline': 4, 'full_consumption_semantic': 1, 'unexpected_success': 1, 'pending_inference': 1, 'unknown': 1}
- migration_status distribution: {'pending_migration': 36, 'projection_limitation': 1, 'migrated_safe': 2, 'migrated_candidate': 1, 'stable_safe_negative': 2}
- top scheduler families:
  - der_full_consumption: 0.9 -> der_full_consumption_v2
  - cipher_aead_lifecycle: 0.65 -> cipher_aead_lifecycle_family_v1
  - asn1_nested_boundary: 0.6 -> asn1_nested_boundary_triage_v1
  - mac_lifecycle: 0.6 -> build_mac_lifecycle_family_v1
  - memory_length_boundary: 0.55 -> manual_classification
  - api_state_machine: 0.45 -> api_state_machine_family_v1
- patterns needing manual confirmation: ['OPENSSL-ISSUE-13860']
- recommended next family: der_full_consumption
- this run did not batch-render, compile, or execute all PoCs.
