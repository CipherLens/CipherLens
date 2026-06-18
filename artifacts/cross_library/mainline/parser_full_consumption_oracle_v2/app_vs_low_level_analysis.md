# App-Level 与 Low-Level DER 解析行为对照

本轮使用小规模 OpenSSL DER 输入验证 `parser_oracle` 的 full-consumption / trailing-garbage 分类能力。核心观察对象是 app-level 命令是否只依据前置合法 DER 对象返回成功，以及 `asn1parse` 是否能对同一输入中的畸形尾部给出拒绝信号。

合法对象加畸形尾部被 app-level 命令接受，不应直接等同于已确认安全问题。原因是不同 OpenSSL 命令和低层解析 API 的输入消费语义可能不同，有些命令可能只承诺解析第一个对象，是否要求完整消费取决于 API contract、调用上下文和上层脚本假设。

不过，这类行为仍值得作为 `semantic_gap_candidate` 继续分析：如果 app-level 命令返回成功，而 low-level/asn1parse 能证明同一输入存在未被完整消费或畸形尾部，那么依赖 exit code 判断“整个 DER 文件有效”的应用脚本可能产生误判风险。尤其是证书、私钥、公钥导入流水线中，脚本若只检查命令成功而不检查输入是否完整消费，可能把“合法前缀 + 非法尾部”当作整体合法输入。

本轮统计中，`semantic_gap_candidate_count` 为 `4`，`unexpected_accept_observation_count` 为 `0`，`negative_control_support_count` 为 `6`。这些标签都属于保守分类，不表示已确认漏洞。

如果后续提交上游，建议表述为：“在特定 app-level DER 命令中观察到合法 DER 前缀后附加畸形尾部仍返回成功的语义差异；该差异可能影响仅依赖 exit code 判断完整输入有效性的调用方，建议明确文档化或提供完整消费检查方式。”避免使用已确认漏洞、可利用性或严重等级等过度表述。
