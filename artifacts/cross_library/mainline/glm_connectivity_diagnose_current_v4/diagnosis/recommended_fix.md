# GLM Connectivity Recommended Fix

This diagnosis does not claim any vulnerability and did not generate slot bindings.

## Primary Fix

- Set an explicit GLM model before retrying, for example `export GLM_MODEL="glm-4.5-flash"`.

## Secondary Checks

- If only `GLM_API_KEY` is configured, also export `ZHIPUAI_API_KEY="$GLM_API_KEY"` for the current repository helper.
- Decide whether the SDK default endpoint is intended; otherwise set `GLM_BASE_URL` or `OPENAI_BASE_URL` for the intended client.
- If the network probe failed, check DNS, proxy, firewall, or TLS interception before retrying a real GLM request.

## Retry Boundary

After fixing the environment, rerun the GLM preflight/slot-filling retry sprint. Do not write generated output to the main knowledge or pattern bank until the GLM request is observable and schema-valid.

## Candidate Codes

- `sdk_missing` (low): Optional client package 'zai' is not installed.
- `sdk_missing` (low): Optional client package 'openai' is not installed.
