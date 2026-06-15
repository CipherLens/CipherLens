# x509_parsing_triage_v1 Input Summary

- Route planner 允许本轮做 `auto_triage`：`x509_parsing` 是 scheduler top-1，证据强度为 medium，且问题主要是路线歧义而不是缺少执行产物。
- `render_cases` / `compile_run` 不允许：A-path gate=false，当前没有 validated recipe-slot mapping、可比较 oracle、或受控 mutation matrix。
- GLM 不允许：A-path gate=false，不能让 LLM/GLM 在无 recipe 约束下补 API contract 或 free-form C。
- 边界：`x509_parsing` 关注证书/CRL/CSR app/API 可见语义；`der_full_consumption` 只管 top-level trailing data/full consumption；`asn1_nested_boundary` 只管内部 ASN.1 边界/崩溃/嵌套 malformed 结构。
