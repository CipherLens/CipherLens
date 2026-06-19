# GLM Connectivity Root Cause Report

- task: `glm_connectivity_root_cause_v1`
- generated_at: `2026-06-19T08:23:47+00:00`
- quality_status: `pass_connection_failure_diagnosed`
- primary_cause: `network_dns_failure`

## Environment

- GLM_API_KEY present: `True`
- ZHIPUAI_API_KEY present: `True`
- ZAI_API_KEY present: `False`
- GLM_MODEL present: `True`
- GLM_BASE_URL present: `True`
- values logged: `false`

## Packages

- zhipuai: `True`
- zai: `False`
- openai: `False`

## Network

- DNS success: `False`
- TLS success: `False`
- explicit base URL present: `True`

## Client Probe

- attempted clients: `4`
- real request attempted: `False`
- success: `False`

## Root Cause Candidates

- `optional_sdk_missing` (low): Optional client package 'zai' is not installed, but zhipuai is the repository GLM SDK path.
- `optional_sdk_missing` (low): Optional client package 'openai' is not installed, but zhipuai is the repository GLM SDK path.
- `network_dns_failure` (medium): DNS lookup for the default GLM endpoint failed in this environment.
- `request_not_attempted_by_diagnosis_policy` (medium): The active zhipuai SDK path is importable and client construction succeeds; this diagnostic did not attempt a real GLM request.

## Guardrails

- slot_bindings_generated: `false`
- adapter_validate_executed: `false`
- render/compile/run executed: `false`
- feedback/pattern bank modified: `false`
- final security claim: `false`
