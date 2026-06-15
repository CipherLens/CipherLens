# x509 Parsing Oracle Candidates

- `safe_reject`: malformed certificate/CRL/CSR safely rejected without crash.
- `app_level_validation_gap`: app-visible wrong-result/wrong-output/status/text/purpose/verify inconsistency.
- `no_crash`: placeholder/local validation未见 sanitizer/SEGV，不把非零退出码当 crash。
- `cross_library_semantic_divergence`: 未来 A/B 需要 mbedTLS/OpenSSL 可比较 API 和 oracle。
- `verification_semantic_gap`: chain/purpose/time/usage/CRL verification observable gap。
- `full_consumption`: 仅作为 DER family delegate，不在本轮重复。
- 禁用标签：`confirmed_vulnerability`, `CVE`, `exploitable`。
