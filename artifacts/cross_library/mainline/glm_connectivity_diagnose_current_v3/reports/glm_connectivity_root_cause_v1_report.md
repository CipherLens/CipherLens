# GLM Connectivity Root Cause Report

- task: `glm_connectivity_root_cause_v1`
- generated_at: `2026-06-19T06:20:19+00:00`
- quality_status: `pass_connection_failure_diagnosed`
- primary_cause: `sdk_missing`

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

- DNS success: `True`
- TLS success: `True`
- explicit base URL present: `True`

## Client Probe

- attempted clients: `4`
- real request attempted: `False`
- success: `False`

## Root Cause Candidates

- `sdk_missing` (low): Optional client package 'zai' is not installed.
- `sdk_missing` (low): Optional client package 'openai' is not installed.

## Guardrails

- slot_bindings_generated: `false`
- adapter_validate_executed: `false`
- render/compile/run executed: `false`
- feedback/pattern bank modified: `false`
- final security claim: `false`
