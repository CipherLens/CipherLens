# GLM Connectivity Root Cause Report

- task: `glm_connectivity_root_cause_v1`
- generated_at: `2026-06-13T10:26:50+00:00`
- quality_status: `pass_model_missing_diagnosed`
- primary_cause: `model_missing`

## Environment

- GLM_API_KEY present: `True`
- ZHIPUAI_API_KEY present: `True`
- ZAI_API_KEY present: `False`
- GLM_MODEL present: `False`
- GLM_BASE_URL present: `False`
- values logged: `false`

## Packages

- zhipuai: `True`
- zai: `False`
- openai: `False`

## Network

- DNS success: `False`
- TLS success: `False`
- explicit base URL present: `False`

## Client Probe

- attempted clients: `4`
- real request attempted: `False`
- success: `False`

## Root Cause Candidates

- `model_missing` (high): GLM_MODEL is not set, so the diagnosis policy did not attempt a real GLM request.
- `base_url_missing` (medium): No explicit GLM/OpenAI-compatible base URL is configured.
- `sdk_missing` (low): Optional client package 'zai' is not installed.
- `sdk_missing` (low): Optional client package 'openai' is not installed.
- `network_dns_failure` (medium): DNS lookup for the default GLM endpoint failed in this environment.
- `unknown_connection_error` (low): The previous sprint reported a generic connection error but did not perform a real request.

## Guardrails

- slot_bindings_generated: `false`
- adapter_validate_executed: `false`
- render/compile/run executed: `false`
- feedback/pattern bank modified: `false`
- confirmed vulnerability claim: `false`
