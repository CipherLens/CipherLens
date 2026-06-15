# x509_parsing Route Contract

family: x509_parsing
scheduler_rank: 1
recommended_route: C_app_level_validation_gap
route_confidence: medium
evidence_strength: medium
known_seeds:
- MBEDTLS-POC-0027
- OPENSSL-ISSUE-11567
- OPENSSL-ISSUE-11772
- OPENSSL-ISSUE-13860
- OPENSSL-ISSUE-14457
- OPENSSL-ISSUE-14675
- OPENSSL-ISSUE-23325
- OPENSSL-ISSUE-29418
- OPENSSL-ISSUE-29574
- OPENSSL-ISSUE-6788
- OPENSSL-ISSUE-9043
known_artifacts:
- artifacts/migrations/mbedtls-poc-0027-tls13-verify-result-propagation/README.md
- datasets/openssl/poc_artifacts/issue_11567/metadata.json
- datasets/openssl/poc_artifacts/issue_11772/metadata.json
- datasets/openssl/poc_artifacts/issue_13860/metadata.json
- datasets/openssl/poc_artifacts/issue_14457/metadata.json
- datasets/openssl/poc_artifacts/issue_14675/metadata.json
- datasets/openssl/poc_artifacts/issue_23325/metadata.json
- datasets/openssl/poc_artifacts/issue_29418/metadata.json
- datasets/openssl/poc_artifacts/issue_29574/metadata.json
- datasets/openssl/poc_artifacts/issue_6788/metadata.json
- datasets/openssl/poc_artifacts/issue_9043/metadata.json
api_groups:
- OBJ_nid2sn
- PEM_encode
- PKCS8::PEM_encode
- SSL_CTX_use_PrivateKey_ASN1
- SSL_CTX_use_certificate_ASN1
- X509_ATTRIBUTE_get0_type
- X509_CA::make_cert
- X509_EXTENSION_free
- X509_Object::choose_sig_format
- X509_STORE_CTX_get_obj_by_subject
- X509_V_ERR_DIFFERENT_CRL_SCOPE
- X509_cmp_time
- X509_delete_ext
- X509_get0_notAfter
- X509_get_ext
- X509_get_ext_count
- X509_get_pubkey
- X509_parse
- X509_verify_cert
- X509v3 Authority Key Identifier
- X509v3 Basic Constraints
- X509v3 Subject Key Identifier
- X509v3 extensions
- authorityKeyIdentifier
- basicConstraints
- crl_crldp_check
- get_crl_score
- keyUsage
- mbedtls_ssl_get_verify_result
- md5WithRSAEncryption
- subjectAltName
- subjectKeyIdentifier
- unknown
oracle_candidates:
- app visible wrong-result / wrong-output
- safe rejection vs accepted malformed certificate/CRL/CSR
- verification result divergence
- sanitizer/null-dereference evidence for D-path seeds only
gate_results:
  evidence_gate:
    actions: []
    passed: true
    strength: medium
  a_path_gate:
    passed: false
    reason: not an eligible A-path family or evidence/mapping/oracle gate did not
      pass
  glm_gate:
    glm_allowed: false
    glm_role: none
allowed_actions:
  auto_triage: true
  auto_render: false
  auto_run: false
  glm: false
blocked_actions:
- render_cases
- compile_run
- GLM slot filling
- free-form C generation
- vulnerability or CVE claim
- Pattern Bank write-back
route_ambiguity:
- C_app_level_validation_gap is plausible because several x509 seeds are app-visible
  wrong-result/wrong-output cases.
- D_crash_sanitizer_evidence_audit remains plausible for seeds such as CSR/ASN.1 NULL
  dereference reports.
- A-path is premature until seed inventory, API grouping, and oracle comparability
  are explicit.
- B-path is possible later for verifier/state-machine style mutations, but controls
  are not defined yet.
relation_to_der_full_consumption: DER full-consumption is already an app-level trailing-data
  validation gap; x509_parsing is broader and must avoid duplicating that exact completed
  C-path unless a new x509-specific app behavior is identified.
relation_to_asn1_nested_boundary: ASN.1 nested boundary is blocked on missing crash
  seed; x509_parsing must first classify seeds into app-visible semantics vs D-path
  crash audit before using ASN.1 evidence.
triage_requirements:
- build x509 seed inventory
- separate semantic/app-level cases from crash/ASN.1 nested boundary cases
- identify OpenSSL app-level x509/verify/crl/req/decoder paths
- define controls and oracle candidates before any render/run
next_task_name: x509_parsing_triage_v1
next_task_goal: Create seed inventory, route disambiguation, API group map, and oracle
  candidates for x509_parsing without render/run.
score_snapshot:
  api_mapping_clarity: 3
  execution_cost: -2
  explanation: 'Status: ready_for_triage.'
  external_validation_penalty: 0
  family: x509_parsing
  final_score: 15
  historical_seed_quality: 5
  mutation_space_quality: 3
  negative_feedback_penalty: 0
  novelty_potential: 4
  oracle_clarity: 2
  prior_positive_signal: 0
  recommended_next_task: x509_parsing_triage_v1
  recommended_route: C_app_level_validation_gap
  seed_missing_penalty: 0

## Interpretation

The contract accepts the scheduler top-1 selection for triage only. It keeps `C_app_level_validation_gap` as a tentative route, while explicitly preserving D/A/B alternatives until seed inventory and oracle abstraction are complete.
