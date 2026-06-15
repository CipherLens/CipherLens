# family_template_generalization_v1 input summary

- 本轮改成 family-level template package，是为了让最终模板表达可迁移的漏洞模式语义，而不是单个 PoC 的偶然实现细节。
- 不能采用 one PoC one template，因为 seed PoC 只提供证据；最终单位应当是 family-level canonical template 或 spec。
- 有 seed 的 family：`pkcs_container_parsing` 使用 `WOLFSSL-POC-0007` / `WOLFSSL-POC-0006`，`asn1_nested_boundary` 使用 `WOLFSSL-POC-0004`。
- 暂时只有 spec 的 family：`x509_parsing`、`tls_protocol_state_lifecycle`、`secure_heap_state_lifecycle`。
- 本轮不生成 OpenSSL / mbedTLS adapter，也不生成 `adapter.yaml`。
- 本轮不调用 GLM；未来只允许 GLM 填 `slot_bindings`。
- 本轮不运行 PoC，不 render case，不 compile/run harness。
