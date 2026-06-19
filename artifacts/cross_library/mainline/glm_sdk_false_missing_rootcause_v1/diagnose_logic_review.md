# GLM SDK False Missing Logic Review

The active repository GLM client imports `from zhipuai import ZhipuAI`; it does not require `zai` or `openai` for the native GLM path.

The false `sdk_missing` root cause came from `analysis/glm_connectivity_diagnose.py`: `root_cause_candidates()` appended the same `sdk_missing` code for every missing package in `("zhipuai", "zai", "openai")`. In this environment `zhipuai` was present, but `zai` and `openai` were absent. Because no higher-priority candidate existed in v4, the first optional missing package (`zai`) became `primary_cause: sdk_missing`.

The diagnosis script also only recorded a coarse package-installed state. It did not separately report whether `zhipuai` imported cleanly, whether `ZhipuAI` was available, or whether local client construction failed before any real request.

Fix applied:

- `package_probe()` now records sanitized import errors and checks that `zhipuai.ZhipuAI` is available.
- `client_probe()` now performs local `ZhipuAI(...)` construction without making a real GLM request.
- missing `zai` and `openai` are reported as `optional_sdk_missing`.
- `root_cause_candidates()` treats only missing/broken `zhipuai` as blocking `sdk_missing` / `sdk_import_failed` / `sdk_version_incompatible`.
- primary cause selection ignores `optional_sdk_missing`.

After the fix, v5 reports `primary_cause: network_dns_failure`, while also recording `primary_sdk_ready: true` and `client_init_success: true` for `zhipuai_sdk`.

