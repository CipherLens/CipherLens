# x509 App-Level Gap Oracle

- C-path 的核心不是 `no_crash`，而是 app-visible semantic gap。
- `malformed_accepted_with_output`: malformed/nonconforming cert 被打印或接受为有意义输出。
- `verify_semantic_gap`: verify 对 semantically invalid cert/chain/CRL/time 给出错误状态。
- `inconsistent_app_behavior`: 同一输入/等价路径在不同 app option 下输出不一致。
- `safe_reject_control`: 作为负控，不是漏洞结论。
- `no_crash_only`: 降级，不足以作为 C-path gap。
