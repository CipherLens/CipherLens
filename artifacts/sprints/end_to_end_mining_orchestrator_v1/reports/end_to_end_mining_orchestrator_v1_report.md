# end_to_end_mining_orchestrator_v1 Report

## Scope

- pipeline stages: 18
- dry-run: true
- GLM called: false
- render/compile/run: false / false / false

## Family State

- ASN.1: external_pending / {'loop_closed': True, 'candidates': 'external_validation_pending', 'external_validation_pending': 3, 'next_gate': 'external_validation_import_gate_v1'}
- PKCS: external_pending / {'seed_ready': True, 'valid_prefix_pipeline_done': True, 'full_consumption_gap_candidate': 2, 'triage': 'caller_must_check_consumption', 'app_level_check': 'external_assigned_or_pending', 'next_gate': 'wait_pkcs_app_level_consumption_check'}
- X.509: missing_capability / {'seed_discovery_done': True, 'der_seed_ready': True, 'pem_seed_ready': True, 'next_stage': 'mutation_planner', 'recommended_next_task': 'x509_valid_prefix_mutation_plan_v1', 'missing_capability': True, 'recommended_module_to_implement': 'mutation/x509_valid_prefix_mutation.py'}

## LLM Policy

- allowed output: ['slot_bindings.yaml']
- forbidden: ['complete C harness', 'adapter_recipes overwrite', 'normalized_templates overwrite', 'mapping gate bypass']
- adapter_validate_required: True

## Next Execution Plan

- top_ready_family: x509_parsing
- top_ready_stage: mutation_planner
- recommended_next_task: x509_valid_prefix_mutation_plan_v1
- status: missing_capability
- missing_capabilities: [{'family': 'x509_parsing', 'stage': 'mutation_planner', 'recommended_module_to_implement': 'mutation/x509_valid_prefix_mutation.py'}]

## Quality

- quality_status: pass
- no vulnerability/CVE/exploitability claim
