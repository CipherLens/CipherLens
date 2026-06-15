# orchestrator_use_generic_mutation_engine_v1 Report

## Scope

- selected family: x509_parsing
- selected stage: mutation_planner
- generic engine used: True
- family-specific mutator required: False

## Mutation Planner

- generated cases: 4
- strategies: ['der_valid_plus_trailing_garbage', 'malformed_only_control', 'near_valid_der_length_delta', 'pem_valid_plus_trailing_garbage']
- next stage: render_plan
- render ready: True

## Policy

- tools core logic: false
- new tools script: false
- render/compile/run: false / false / false
- feedback/knowledge/pattern bank: false / false / false
- GLM called: false
- confirmed vulnerability claim: false

## Quality

- quality_status: pass
