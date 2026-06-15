# x509 RAG Evidence Summary

- RAG 成功: `True`
- 查询数: `3`
- RAG 作为辅助召回，不作为漏洞确认依据。
- 支持 C-path：OpenSSL x509/verify/crl app-level wrong-result/wrong-output seed 多。
- 支持 D-path：CSR/ASN.1 NULL deref seed 存在，但需要 strict reproduction 和 sanitizer 证据。
- 不支持当前 A-path：还缺 source/target API 对齐和 comparable oracle。
