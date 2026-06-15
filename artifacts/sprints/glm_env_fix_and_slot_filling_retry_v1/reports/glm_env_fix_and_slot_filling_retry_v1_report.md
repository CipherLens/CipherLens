# glm_env_fix_and_slot_filling_retry_v1 Report

## Previous Baseline

- previous_sprint: artifacts/sprints/rag_glm_baseline_and_known_pattern_gate_v1
- rag_lookup_reused: True
- mapping_gate_reused: True
- slot_filling_plan_loaded: True

## GLM

- glm_required: True
- api_key_present: True
- api_key_logged: false
- base_url_present: False
- glm_model_present: True
- network_endpoint_checked: True
- dns_success: False
- glm_called: False
- glm_request_count: 0
- glm_response_count: 0
- unavailable_reason: DNS/endpoint check failed before GLM request

## Validation

- slot_bindings_generated: False
- slot_bindings_placeholder: True
- slot_bindings_schema_valid: False
- mapping_gate_validate_executed: True
- adapter_validate_executed: False
- mapping_gate_bypassed: False
- invalid_glm_output: False

## Policy

No tools script, API key logging, render, compile, run, feedback, pattern-bank
write, adapter recipe modification, normalized template modification, C-code
generation by GLM, git action, CVE, exploitability, or confirmed vulnerability
claim was produced.

## Quality

- quality_status: blocked_network_or_endpoint
