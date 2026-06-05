# OpenSSL 剩余 PoC 接入计划

## 1. 已完成样本复盘

### issue_8980：EVP_CIPHER_CTX_copy uninitialized state

`issue_8980` 的核心触发路径来自：

- `datasets/openssl/poc_artifacts/issue_8980/poc.c`
- `knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-8980.yaml`
- `normalized_templates/openssl/evp_cipher_ctx_copy_uninit_state/`
- `migration_candidates/openssl/evp_cipher_ctx_copy_uninit_state/candidates.yaml`
- `migration_candidates/openssl/evp_cipher_ctx_copy_uninit_state/candidates_with_evidence.yaml`
- `migration_candidates/openssl_same/evp_cipher_ctx_copy_uninit_state/candidates.yaml`
- `artifacts/migrations/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/README.md`
- `artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/README.md`

原始 OpenSSL 触发序列是：

```text
EVP_CIPHER_CTX_new
-> EVP_aes_128_gcm
-> EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)
-> EVP_CIPHER_CTX_new
-> EVP_CIPHER_CTX_copy(dst, src)
```

这个样本没有进入 OpenSSL -> mbedTLS 的跨库主链路，原因很明确：`EVP_CIPHER_CTX_copy` 是漏洞路径的定义性操作，而 mbedTLS 公开 API 中没有 cipher/GCM/PSA AEAD context copy 或 clone API。已有候选评分也反映了这一点：

- `mbedtls_cipher_init / mbedtls_cipher_setup / mbedtls_cipher_setkey`: final_score 32，`vulnerability_path: 5`
- `psa_aead_encrypt_setup / psa_aead_update / psa_aead_abort`: final_score 26，`vulnerability_path: 5`
- `mbedtls_gcm_init / mbedtls_gcm_setkey / mbedtls_gcm_starts`: final_score 29，`vulnerability_path: 5`
- `no_equivalent_public_api`: final_score 0

因此当前结论是：

```text
migration_not_applicable / no_equivalent_public_api
```

不过 `issue_8980` 已完成 same-library equivalent API batch testing。`migration_candidates/openssl_same/evp_cipher_ctx_copy_uninit_state/candidates.yaml` 中确认：

- `EVP_CIPHER_CTX_copy` 是 same_api_regression，分数 100。
- `EVP_CIPHER_CTX_dup` 是 same_library_equivalent_api，分数 96。
- `EVP_CIPHER_CTX_dup` 在 OpenSSL 3.5.5 中是公开 API，内部走 `EVP_CIPHER_CTX_copy` 路径。

实际批量结果在：

- `artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/fixed_openssl_3_5_5/cases/`
- `artifacts/regressions/openssl-issue-8980-evp-cipher-ctx-copy-uninit-state/results/issue_8980_dup_batch_summary.json`

结果摘要：

```text
total_cases: 28
compile_ok: 28
run_ok: 28
safe_fixed_behavior: 28
crash_candidate: 0
needs_triage: 0
```

这个样本的价值是提供了一个“不可跨库迁移也要留下证据链”的标准做法：当目标库缺少定义性 API 时，不让 LLM 生成弱投影 harness，而是明确给出 `migration_not_applicable`，必要时转向同库版本回归。

### issue_19524：public-only key sign capability mismatch

`issue_19524` 是当前 OpenSSL -> mbedTLS recipe-slot 主链路的完整样本。

关键输入和产物：

- 原始 artifact：`datasets/openssl/poc_artifacts/issue_19524/`
- pattern：`knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-19524.yaml`
- normalized template：`normalized_templates/openssl/pkey_public_only_sign_null_deref/`
- candidate：`migration_candidates/openssl/pkey_public_only_sign_null_deref/candidates.yaml`
- candidate evidence：`migration_candidates/openssl/pkey_public_only_sign_null_deref/candidates_with_evidence.yaml`
- adapter recipe：`adapter_recipes/mbedtls/psa_sign_message.pkey_capability_mismatch_oracle.yaml`
- LLM adapter：`artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/adapters_recipe_llm/PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF/mbedtls_psa_sign_message/adapter.yaml`
- validated adapter：`artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/adapters_recipe_llm_validated/PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF/mbedtls_psa_sign_message/adapter.yaml`
- cross template：`artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/cross_templates_recipe/PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF/mbedtls_psa_sign_message/`
- runner results：`artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/`

原始漏洞语义：

```text
EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, ...)
-> EVP_DigestSignInit(...)
-> EVP_DigestSign(...)
```

affected OpenSSL 版本在 public-only ED25519/ED448 key 进入 sign 路径时可能 NULL deref；当前 OpenSSL 3.5.5 表现为安全拒绝。

迁移目标选择：

- primary target：`psa_sign_message`
- family：`pkey_capability_mismatch_oracle`
- oracle：`public_key_sign_rejection_oracle`
- 实际 cross template 中因当前 mbedTLS 4.1.0 build 未启用 Ed25519 PSA，使用 ECDSA/SECP_R1 + `psa_sign_hash` 表达同一个“public-only key 不允许 sign”的能力不匹配 oracle。

最终结果在：

- `artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/run_recipe.jsonl`
- `artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/run_recipe.summary.json`
- `artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/run_recipe.verdicts.jsonl`
- `artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/run_recipe.migration_summary.json`
- `artifacts/migrations/openssl-issue-19524-pkey-public-only-sign-null-deref/results/run_recipe.migration_pairs.jsonl`

结果摘要：

```text
total_cases: 64
single-side verdict: safe_reject_behavior 64
total_pairs: 32
migration_verdict: migrated_safe 32
```

最终结论：

```text
migrated_safe
```

含义是：漏洞模式成功迁移，OpenSSL 3.5.5 和 mbedTLS PSA 都对 public-only key signing 做了安全拒绝，没有 crash 或 sanitizer 信号。

## 2. 当前主链路说明

当前主链路是 recipe-slot 驱动的跨库漏洞模式迁移链路：

```text
PoC evidence
  -> normalized source template
  -> template_meta.yaml
  -> mask_report.yaml
  -> ast_mask_report.yaml
  -> selected_mask_units.yaml
  -> candidates.yaml
  -> candidates_with_evidence.yaml
  -> adapter recipe
  -> LLM slot_bindings
  -> adapter_validate
  -> cross template
  -> rendered cases
  -> runner compile/run
  -> analyze_results
  -> analyze_cross_results
  -> final verdict
```

对应项目文件和脚本：

- PoC evidence：
  - `datasets/openssl/poc_artifacts/*/metadata.json`
  - `datasets/openssl/poc_artifacts/*/poc.c`
  - `knowledge_raw/poc_patterns/openssl/*.yaml`
- normalized template：
  - `normalized_templates/openssl/*/tmpl_openssl.c`
  - `normalized_templates/openssl/*/template_meta.yaml`
  - `normalized_templates/openssl/*/mask_report.yaml`
  - `normalized_templates/openssl/*/ast_mask_report.yaml`
  - `normalized_templates/openssl/*/selected_mask_units.yaml`
- candidate/evidence：
  - `migration_candidates/openssl/*/candidates.yaml`
  - `migration_candidates/openssl/*/candidates_with_evidence.yaml`
  - `migration/candidate_mapper.py`
  - `migration/evidence_collector.py`
- recipe-slot adapter：
  - `adapter_recipes/*/*.yaml`
  - `migration/adapter_filler.py`
  - `migration/adapter_validate.py`
- cross template：
  - `template_maker/cross_generator_from_adapters.py`
  - `artifacts/migrations/*/cross_templates_recipe/`
- rendered cases：
  - `template_maker/render_cases.py`
  - `artifacts/migrations/*/rendered_cases_recipe/`
- runner and verdict：
  - `runner/compile_run.py`
  - `runner/analyze_results.py`
  - `runner/analyze_cross_results.py`
  - `artifacts/migrations/*/results/run_recipe.*`

文字流程图：

```text
PoC evidence
  真实 issue、metadata、PoC、root cause、oracle

-> template
  将源库 API 路径变成带 slot 的 normalized source template

-> mask reports
  标出哪些片段可变，哪些片段是不可破坏的核心触发路径

-> candidates_with_evidence
  用 RAG/evidence 评估目标库 API 是否保留 operation family、function behavior、
  parameter structure、vulnerability path、harness feasibility

-> adapter recipe
  选择目标 API 对应的固定 recipe，定义 family、oracle、allowed_slots、forbidden_terms

-> slot_bindings
  LLM/GLM 只填写 recipe 允许的 slot，不生成 C harness

-> cross template
  固定 renderer 根据 recipe + slot_bindings 生成 `tmpl_openssl.c` / `tmpl_mbedtls.c`

-> rendered cases
  `render_cases.py` 展开 mutation_points，生成 paired source/target C cases

-> runner
  `compile_run.py` 编译运行，`analyze_results.py` 做单侧 verdict

-> verdict
  `analyze_cross_results.py` 按 source/target pair 输出 migrated_safe、
  migrated_bug_candidate、migration_not_applicable 等最终结论
```

## 3. 剩余 28 个 PoC 分类

以下分类不包含已处理的 `issue_8980` 和 `issue_19524`。

### P0：最适合立即接入

- `issue_21935`：self-contained PKEY/RSA sign 路径，可复用 `issue_19524` 的 pkey sign safe-reject 思路，优先接入。

### P1：需要新增少量 family/oracle/recipe

- `issue_18659`：self-contained cleanup 后再 unload，适合 `object_state_lifecycle`，但 mbedTLS cleanup 等价 API 需要挑选。
- `issue_22842`：self-contained EVP/MAC context 状态查询，适合 `object_state_lifecycle` 或 `invalid_parameter_setup_oracle`，需要 mbedTLS md/HMAC recipe。
- `issue_28669`：self-contained 且本地可见 segfault，但 `CRYPTO_secure_used` 是 OpenSSL secure heap 专属，适合先做证据链后大概率判不可迁移。
- `issue_29645`：self-contained BIO_set_data/BIO_free 状态生命周期，可能可做 object lifecycle，但 mbedTLS 无 BIO 等价对象，需要语义投影评估。

### P2：需要较多工程工作

- `issue_6788`：CRL/X509 wrong result，依赖外部输入和 X509 verify 语义，适合后续 `x509_verify_semantic`。
- `issue_9043`：CSR/ASN1 NULL deref，当前缺原始输入，需构造 CSR parser/text-output harness。
- `issue_11567`：X509/ASN1 wrong result，依赖证书语义和 placeholder input，迁移成本高。
- `issue_11772`：X509 time parsing wrong result，可参考 `x509_asn1_inner_boundary`，但需要精确 ASN1 时间输入。
- `issue_13860`：X509 public key output 行为差异，语义不清且依赖输入，需人工 triage。
- `issue_14457`：X509 extensions wrong output，依赖配置/证书扩展语义，适合后续 x509 semantic family。
- `issue_14675`：X509 verify 多证书处理，CLI 行为到 C API 转换成本高。
- `issue_15899`：BN/ASN1 NULL deref，可能走 crash sanitizer，但需要原始证书或可控 ASN1 输入。
- `issue_16196`：REQ/ASN1 BN_print NULL deref，依赖 CSR 输入，需 parser harness。
- `issue_18168`：WPACKET/DER/RSA assertion，路径偏内部 DER writer，公开 API 投影复杂。
- `issue_23325`：X509/CRL wrong result，CRL scope 语义复杂且依赖原始输入。
- `issue_26106`：PKCS12/X509_ALGOR NULL deref，需要 PKCS12 输入和解析路径。
- `issue_27572`：CMP/ASN1 wrong output，CLI/ASN1 语义投影成本高。
- `issue_29418`：X509 purpose/extensions wrong result，需要 X509 extension semantic harness。
- `issue_29574`：X509 corrupted state，依赖 malformed certificate/private-key ASN1 输入。
- `issue_30581`：PKCS12/ASN1 NULL deref，依赖 PKCS12 PBMAC1 输入，适合后续 crash sanitizer。

### 暂缓：migration_not_applicable 或 OpenSSL-specific

- `issue_2630`：OpenSSL secure heap/BIO_s_secmem 专属，且 main 默认不触发 PoC 路径。
- `issue_8435`：SM2 行为差异，标准 mbedTLS build 中 SM2 等价支持不足。
- `issue_17715`：RAND_DRBG/EVP 内部 cipher_data 初始化问题，内部状态路径难以公开 API 化。
- `issue_22388`：CMS/X25519/X448 support 行为，mbedTLS 无 CMS 等价主链路。
- `issue_30291`：CMS/ED448 regression，CMS 是主要阻塞点。
- `issue_30432`：DSA SHA384/512 verify/OID 行为，mbedTLS 现代版本 DSA 支持有限。
- `issue_30889`：PKEY/ML-DSA interactive encode/encrypt 路径，算法和 CLI 交互语义都不适合立即迁移。

## 4. 下一步优先处理 issue_21935

`issue_21935` 当前文件：

- `datasets/openssl/poc_artifacts/issue_21935/metadata.json`
- `datasets/openssl/poc_artifacts/issue_21935/poc.c`
- `datasets/openssl/poc_artifacts/issue_21935/README.md`
- `datasets/openssl/poc_artifacts/issue_21935/run.log`
- `datasets/openssl/poc_artifacts/issue_21935/valgrind.log`

当前 PoC 路径：

```text
EVP_PKEY_new
-> RSA_new
-> BN_dec2bn(n=3233, e=17, d=2753)
-> RSA_set0_key
-> EVP_PKEY_assign_RSA
-> EVP_MD_CTX_new
-> EVP_DigestSignInit
```

当前 `run.log` 只显示：

```text
EVP_DigestSignInit returned 1
```

也就是说当前 RAG-seed PoC 验证了 API path 能进入签名初始化，但还没有完整执行 `EVP_DigestSign`。接入时应把 source template 补到真正触发 sign attempt，否则 oracle 会偏弱。

### 可复用 issue_19524 的内容

可复用：

- family 思路：`pkey_capability_mismatch_oracle`
- oracle 思路：sign operation 必须安全拒绝不满足签名能力/私钥有效性的 key
- runner 结果分类：`safe_reject_behavior`、`migrated_safe`、`migrated_bug_candidate`
- adapter-slot 机制：
  - `migration/adapter_filler.py`
  - `migration/adapter_validate.py`
  - `template_maker/cross_generator_from_adapters.py`
  - `template_maker/render_cases.py`
- 结果目录布局：
  - `artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/adapters_recipe_llm/`
  - `artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/adapters_recipe_llm_validated/`
  - `artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/cross_templates_recipe/`
  - `artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/rendered_cases_recipe/`
  - `artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/`

不能直接复用的部分：

- `issue_19524` 是 ED25519 public-only raw public key。
- `issue_21935` 是 RSA tiny/invalid key material，问题更像 invalid private key / malformed key sign rejection。
- 现有 `adapter_recipes/mbedtls/psa_sign_message.pkey_capability_mismatch_oracle.yaml` 面向 public-only EdDSA/ECDSA，不足以准确表达 RSA tiny-key 语义。

### 需要新增的文件

建议新增：

```text
knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-21935.yaml
normalized_templates/openssl/rsa_tiny_key_digest_sign_null_deref/tmpl_openssl.c
normalized_templates/openssl/rsa_tiny_key_digest_sign_null_deref/template_meta.yaml
normalized_templates/openssl/rsa_tiny_key_digest_sign_null_deref/mask_report.yaml
normalized_templates/openssl/rsa_tiny_key_digest_sign_null_deref/ast_mask_report.yaml
normalized_templates/openssl/rsa_tiny_key_digest_sign_null_deref/selected_mask_units.yaml
migration_candidates/openssl/rsa_tiny_key_digest_sign_null_deref/candidates.yaml
migration_candidates/openssl/rsa_tiny_key_digest_sign_null_deref/candidates_with_evidence.yaml
adapter_recipes/mbedtls/psa_sign_hash.pkey_capability_mismatch_oracle.yaml
```

如果不想扩大现有 family 名称，也可以在 `pkey_capability_mismatch_oracle` 下新增 oracle type，例如：

```text
invalid_private_key_sign_rejection_oracle
```

但需要同步更新：

- `config/harness_families.yaml`
- `migration/adapter_validate.py`
- `template_maker/cross_generator_from_adapters.py`
- `runner/analyze_results.py`

### 建议 mask slots

```text
RSA_N
RSA_E
RSA_D
MD_ALG
MESSAGE_BYTES
MESSAGE_LEN
SIGN_STAGE
```

不可变核心片段：

```text
RSA_set0_key
EVP_PKEY_assign_RSA
EVP_DigestSignInit
EVP_DigestSign
```

### 预计生成的结果文件

```text
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/adapters_recipe_llm/.../adapter.yaml
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/adapters_recipe_llm_validated/.../adapter.yaml
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/cross_templates_recipe/.../tmpl_openssl.c
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/cross_templates_recipe/.../tmpl_mbedtls.c
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/cross_templates_recipe/.../template_meta.yaml
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/cross_templates_recipe/.../cross_mapping.yaml
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/run_recipe.jsonl
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/run_recipe.summary.json
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/run_recipe.verdicts.jsonl
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/run_recipe.migration_summary.json
artifacts/migrations/openssl-issue-21935-rsa-tiny-key-digestsign-null-deref/results/run_recipe.migration_pairs.jsonl
```

### 可能失败点

- 当前 PoC 未调用 `EVP_DigestSign`，source template 如果不补强会导致 oracle 不充分。
- mbedTLS/PSA 对极小 RSA key 可能在 import/generate 阶段直接拒绝，无法到达 sign path；这可能是 `migrated_safe`，也可能需要标记为 semantic projection limitation。
- RSA key import 需要完整私钥参数时，只有 `n/e/d` 可能不足以构造 PSA private key。
- 如果改用 public-only RSA，则会偏离 `issue_21935` 的 tiny invalid private-key 语义，不能简单套用 19524。
- 需要避免把 `BN_new`、`RSA_new` 等 OpenSSL 残留放进 mbedTLS slot bindings。

## 5. 再处理 issue_22842

`issue_22842` 当前文件：

- `datasets/openssl/poc_artifacts/issue_22842/metadata.json`
- `datasets/openssl/poc_artifacts/issue_22842/poc.c`
- `datasets/openssl/poc_artifacts/issue_22842/README.md`
- `datasets/openssl/poc_artifacts/issue_22842/run.log`
- `datasets/openssl/poc_artifacts/issue_22842/valgrind.log`

原始 root cause：

```text
NULL pointer dereference in EVP_MAC_CTX_get_mac_size()
due to uninitialized algctx cipher struct
```

metadata 中的原始 reproduction command 是：

```text
EVP_MAC_CTX_new()
EVP_MAC_CTX_get_mac_size()
```

但当前 `poc.c` 实际执行的是：

```text
EVP_MAC_fetch("HMAC")
-> EVP_MAC_CTX_new
-> EVP_MAC_init(ctx, key, ..., digest=SHA256)
-> EVP_MAC_CTX_get_mac_size
```

当前 `run.log` 显示：

```text
EVP_MAC_init returned 1
EVP_MAC_CTX_get_mac_size returned 32
```

因此接入前必须决定 source template 是否包含两个状态：

```text
STATE_A: get_mac_size before init
STATE_B: init then get_mac_size
```

### 用 object_state_lifecycle 表达

可表达为 MAC context 生命周期状态查询 oracle：

```text
EVP_MAC_fetch
-> EVP_MAC_CTX_new
-> optional EVP_MAC_init
-> EVP_MAC_CTX_get_mac_size
-> observe size / error / crash
```

安全行为：

```text
未初始化状态下安全返回 0 或错误，不 crash
已初始化状态下返回正确 MAC size，不 crash
```

bug 行为：

```text
EVP_MAC_CTX_get_mac_size 在未初始化 algctx 上 SEGV / ASAN / UBSAN
```

这个 family 可以参考：

- `config/harness_families.yaml` 中的 `object_state_lifecycle`
- `adapter_recipes/openssl/ASN1_STRING_set.object_state_lifecycle.yaml`
- `template_maker/cross_generator_from_adapters.py` 中现有 `object_state_lifecycle` renderer
- `runner/analyze_results.py` 中 object lifecycle verdict patterns

但现有 object lifecycle renderer 只支持 `ASN1_STRING_set`，所以 22842 需要新增 mbedTLS MAC/md 专用 renderer。

### 用 invalid_parameter_setup_oracle 表达

也可表达为 invalid setup/state query：

```text
query size before required setup
```

安全行为：

```text
返回 0 / error / safe reject
```

但 `EVP_MAC_CTX_get_mac_size` 更像状态查询而不是参数设置，因此优先建议 `object_state_lifecycle`，`invalid_parameter_setup_oracle` 作为备选。

### 可能目标 API

mbedTLS legacy md/HMAC 路径：

```text
mbedtls_md_init
mbedtls_md_setup
mbedtls_md_hmac_starts
mbedtls_md_get_size
mbedtls_md_get_size_from_type
mbedtls_md_free
```

PSA MAC 路径：

```text
psa_mac_sign_setup
psa_mac_update
psa_mac_sign_finish
psa_mac_abort
```

优先建议 legacy md/HMAC，因为它更接近 `HMAC-SHA256 size query`，且已有 inventory 中建议目标 API 是 `mbedtls_md_hmac_starts / mbedtls_md_get_size`。

### 需要新增的 family/recipe

如果沿用现有 family：

```text
adapter_recipes/mbedtls/mbedtls_md_get_size.object_state_lifecycle.yaml
```

可能 slots：

```text
md_type: MBEDTLS_MD_SHA256
call_get_size_before_setup: 0/1
call_hmac_starts: 0/1
key_bytes
key_len
message_len
```

需要同步新增 renderer 支持：

- `template_maker/cross_generator_from_adapters.py`
  - 支持 target API `mbedtls_md_get_size` 或 `mbedtls_md_hmac_starts`
  - 支持 `object_state_lifecycle` 的 MAC/md 状态模板
- `migration/adapter_validate.py`
  - 允许该 target API 使用 `object_state_lifecycle`
  - 加入 forbidden residue 检查，防止 OpenSSL EVP_MAC 残留进入 mbedTLS slot
- `runner/analyze_results.py`
  - 增加 MAC size lifecycle 的 safe/triage/bug 输出 pattern

如果新增更精确 family，可命名为：

```text
mac_context_state_lifecycle
```

但除非后续有多个 MAC context PoC，否则建议先复用 `object_state_lifecycle`，避免过早扩展 family。

## 6. 工程注意事项

### LLM 只生成 slot_bindings

必须延续 `issue_19524` 的 recipe-slot 方式。`migration/adapter_filler.py` 的 recipe prompt 已要求：

```text
Output only one top-level field: slot_bindings.
Do not output init_block, input_construction_block, trigger_block, cleanup_block, oracle_strategy, or C code.
```

后续新增 recipe 时，也要保证：

- `allowed_slots` 明确且足够小。
- `forbidden_terms` 覆盖源库残留 API。
- recipe 默认值可独立生成可编译 harness。

### 不允许 free-form C harness

不要让 LLM 生成完整 C 文件，也不要在 adapter 里写自由 C block。原因：

- 会绕过 `adapter_validate.py` 的 recipe-slot 约束。
- 容易破坏 source vulnerability path。
- 容易混入 OpenSSL/mbedTLS 残留 API。
- 难以复现和批量比较。

正确模式是：

```text
adapter_recipe 固定 C skeleton
LLM 只填 slot_bindings
renderer 生成 tmpl_*.c
render_cases 展开 mutation points
runner 统一分析 verdict
```

### 不要写单个 PoC 专用硬编码

新增代码应按 family/recipe 复用，不应只服务一个 issue 编号。例如：

- `issue_21935` 不应写 `render_issue_21935_only()`。
- 应写成 RSA/PK signing rejection 类 renderer，后续可复用到其他 PKEY PoC。
- `issue_22842` 不应写 `EVP_MAC_CTX_get_mac_size` 专用 mbedTLS 结果判断。
- 应抽象成 MAC/md context state lifecycle 或 object_state_lifecycle 的一个 target renderer。

PoC-specific 内容应留在：

```text
knowledge_raw/poc_patterns/openssl/OPENSSL-ISSUE-*.yaml
normalized_templates/openssl/*/
migration_candidates/openssl/*/
artifacts/migrations/openssl-issue-*/
```

family-level 逻辑才进入：

```text
config/harness_families.yaml
adapter_recipes/
migration/adapter_validate.py
template_maker/cross_generator_from_adapters.py
runner/analyze_results.py
runner/analyze_cross_results.py
```

### 区分最终 verdict

后续报告和结果文件必须区分以下结论：

```text
migrated_safe
```

漏洞模式已迁移，source/target 当前版本都安全拒绝或安全处理。`issue_19524` 当前属于此类。

```text
migrated_bug_candidate
```

target 在迁移后的漏洞模式下出现 crash、sanitizer signal 或明显 semantic violation。需要人工确认是否是真实新 bug。

```text
migration_not_applicable
```

目标库缺少定义性 API 或 harness 无法保留 vulnerability path。`issue_8980` 的 OpenSSL -> mbedTLS 结论属于此类。

```text
source_bug_target_safe
```

source 侧 buggy/fixed regression 中 source 表现为 bug，target 安全；适合同库或历史版本对比。

```text
migration_semantic_projection_limitation
```

目标 API 只能表达弱语义投影，不能证明迁移成功或失败。`issue_22842` 如果只用 `mbedtls_md_get_size_from_type` 而没有 context state，可能落入此类。

### 优先级执行建议

建议顺序：

```text
1. 以 issue_19524 为 golden path，确认 recipe-slot 产物链条。
2. 接入 issue_21935，扩展 PKEY sign rejection 到 RSA tiny/invalid key。
3. 接入 issue_22842，新增 mbedTLS md/HMAC lifecycle recipe 和 renderer。
4. 对 P1/P2 issue 批量生成 candidates.yaml，先筛掉 no_equivalent_public_api。
5. 对暂缓类 issue 输出 migration_not_applicable 证据链，不强行生成 harness。
```
