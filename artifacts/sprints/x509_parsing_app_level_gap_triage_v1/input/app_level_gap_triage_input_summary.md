# x509 App-Level Gap Triage Input Summary

- 本轮只聚焦上一轮 `C_app_level_validation_gap` seeds，因为 D/A/overlap 已被明确隔离。
- C-path seed 总数: `7`
- 排除 seed:
  - `MBEDTLS-POC-0027`: A-path potential, blocked in current sprint; needs future tls_verify_result_semantic family.
  - `OPENSSL-ISSUE-13860`: oracle or issue semantics unclear; not C-path candidate yet.
  - `OPENSSL-ISSUE-29574`: ASN.1 nested-boundary/corrupted-state overlap, removed from pure x509 C-path.
  - `OPENSSL-ISSUE-9043`: D-path crash/sanitizer audit, not app-level validation-gap C-path.
- 本轮 render/run: `false`
- 本轮 GLM: `false`
