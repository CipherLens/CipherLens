# X.509 Issue Candidate Summary

## 1. 问题来源

来自 `orchestrator_execute_x509_compile_run_analyze_v1` 的 `full-consumption gap candidate`。

## 2. 当前 observed behavior

候选 DER 输入在 harness 中被 OpenSSL `d2i_X509` 接受，但 `consumed_len < input_len`。

## 3. harness/oracle 证据

- candidate count: 1
- oracle accepted: [1]
- oracle full_consumption: [0]

## 4. app-level replay 结果

- app replay attempted: true
- app-level accepted: True
- meaningful output: True

## 5. malformed-only control 结果

- generated: True
- rejected: True

## 6. 当前分类

`app_level_validation_gap_candidate`

## 7. 是否建议准备 issue

建议先准备 issue-level semantic candidate 材料并请求外部验证；目前不能给出 CVE 或 exploitable 结论。

## 8. 后续最小复现建议

保留 candidate DER、malformed-only control、三条 `openssl x509` replay 命令及其 stdout/stderr，复核应用层是否应拒绝 trailing garbage。
