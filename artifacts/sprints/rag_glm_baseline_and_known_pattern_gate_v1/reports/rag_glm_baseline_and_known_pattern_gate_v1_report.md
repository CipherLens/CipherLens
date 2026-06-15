# rag_glm_baseline_and_known_pattern_gate_v1 Report

## Knowledge

- families: ['pkey_parsing', 'pkcs8_parsing', 'cms_container_parsing', 'x509_crl_parsing']
- family_knowledge_added: True
- api_cards_added: True
- family_profiles_linked_to_rag: True

## Baseline Flow

- rag_lookup_executed: True
- mapping_gate_executed: True
- slot_filling_plan_generated: True
- glm_required: True
- glm_called: False
- slot_bindings_generated: False
- adapter_validate_executed: False
- unavailable_reason: Connection error.

## Known Pattern Gate

- pattern_id: der_single_object_trailing_garbage_full_consumption
- stop_campaign_on_repeat: False
- stop_campaign_on_crash_or_sanitizer: true
- stop_campaign_on_new_semantic_class: true

## Policy

No tools script, render, compile, run, main feedback, pattern-bank write,
adapter recipe modification, normalized template modification, C-code generation
by GLM, git action, CVE, exploitability, or confirmed vulnerability claim was
produced.

## Quality

- quality_status: blocked_glm_unavailable
