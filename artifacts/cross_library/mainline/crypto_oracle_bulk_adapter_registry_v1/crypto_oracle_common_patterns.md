# 密码学库常见 Oracle 模式

密码学库测试不能只看 crash。很多重要结果是语义层面的：解析是否完整消费输入、序列化 roundtrip 是否保持对象语义、签名和验证是否一致、AEAD tag 篡改是否按预期失败、MAC/Digest streaming 与 one-shot 是否一致，以及状态机在 failed-init、reset、reuse 后是否安全收敛。

因此需要区分 parser、roundtrip、crypto semantic、lifecycle、negative control、differential 和 execution 等 oracle。execution oracle 负责程序级异常；parser oracle 负责 DER/PEM/ASN.1/PKCS/X.509/PKEY 输入结构；roundtrip oracle 负责 parse/export/parse 或 bytes/string 转换；crypto semantic oracle 负责 encrypt/decrypt、sign/verify、MAC/Digest 等语义不变量；lifecycle oracle 负责 API 状态机；negative control oracle 负责确认“应该失败”的输入确实失败；differential oracle 负责跨库、跨版本或 app-level vs low-level 对照。

normal reject 不能当作问题，因为畸形输入被拒绝通常正是安全行为。modified tag 或 modified signature 被拒绝通常也是 expected behavior，应该记录为 negative-control baseline。只有当 negative control 在有效 API contract 下被接受，或者 app-level success 与 low-level full-consumption gap 同时出现时，才保守标记为 `unexpected_accept_observation` 或 `semantic_gap_candidate`，并进入后续人工 triage。

这套 adapter registry 的目的，是让不同 campaign 不再各自手写 oracle。每个 campaign 只需要输出最小统一字段，adapter 将其映射为 central dispatcher 输入，再由 dispatcher 统一给出 baseline、observation、unsupported、invalid contract 或保守 candidate 标签。
