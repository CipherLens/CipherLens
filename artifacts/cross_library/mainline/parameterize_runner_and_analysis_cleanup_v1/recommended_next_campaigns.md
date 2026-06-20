# Recommended next campaigns

1. 先用参数化 runner 跑 ready targets 的现有 family smoke。
2. 再扩展 execution-mode 到 existing_harness / compile_run。
3. 然后接 Wycheproof seed bridge。
4. wolfSSL 等 build 修复后再加入全量 target。

推荐本地 WSL 命令：

```bash
PYTHONPATH=. python3 analysis/full_mainline_glm_oracle_campaign.py   --repo-root .   --out-dir artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1   --targets mbedtls-3.6.4-asan,mbedtls-4.1.0-asan,botan-3.10.0-asan   --families pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption   --seed-source mixed   --execution-mode syntax_only   --oracle-mode dispatch   --max-families 5   --max-cases 60   --max-compile-jobs 80   --probe-mode live
```

Codex 环境不能联网时，把 `--probe-mode live` 换成 `--probe-mode existing`。
