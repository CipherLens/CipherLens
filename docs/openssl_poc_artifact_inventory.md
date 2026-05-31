# OpenSSL PoC Artifact Inventory

Generated: 2026-05-31
Source: `datasets/openssl/poc_artifacts/`

---

## 1. Scope

本 inventory 覆盖 `datasets/openssl/poc_artifacts/` 下的全部 30 个 OpenSSL issue artifact 目录。
每个目录对应一个 OpenSSL GitHub issue，包含 metadata.json、poc.c、run.sh，
以及可能的 inputs/ 子目录、README.md 等。

本 inventory 用于评估哪些 issue 适合在当前 recipe-slot 框架下进行 OpenSSL → mbedTLS
的跨库漏洞路径迁移。

**重要说明：**
- 所有 30 个 issue 的 `strict_reproduction` 均为 `false`。
- 任何标注 `local_test_result: compiled_and_executed_no_valgrind_error` 的 issue，只能说明
  在当前链接库下本地执行正常，**不能说明原始漏洞已严格复现**。
- 标注 `missing_original_input: true` 的 issue，使用的是替代输入，原始触发输入缺失，
  **不能认定为已复现漏洞触发路径**。
- `issue_2630` 的 `main()` 中两个关键函数均被注释掉（`/* example1(); */`、`/* example2(); */`），
  默认执行不触发任何 PoC 路径。

---

## 2. Global Summary

| 统计项 | 数量 |
|---|---|
| **Total issues** | 30 |
| `strict_reproduction = false` | 30 (全部) |
| `strict_reproduction = true` | 0 |
| **Artifact class: A_ast_ready** | 4 (issue_2630, 8980, 18659, 28669) |
| **Artifact class: B2_cli_to_c_candidate** | 21 |
| **Artifact class: C_rag_seed_to_c_candidate** | 5 (issue_9043, 19524, 21935, 22842, 29645) |
| **Has external inputs dir with files** | 15 |
| **Missing original input** | 23 |
| **Needs external file input at runtime** | 22 |
| **Self-contained (no external file)** | 8 (issue_2630, 8980, 18659, 19524, 21935, 22842, 28669, 29645) |
| **main() has commented-out calls (不触发 PoC)** | 1 (issue_2630) |

**trigger_behavior 分布：**
| Trigger | Count |
|---|---|
| NULL_DEREFERENCE_CRASH | 10 |
| WRONG_RESULT | 7 |
| SEGV | 4 |
| WRONG_OUTPUT | 2 |
| ASSERTION_FAILURE | 1 |
| VERIFY_ERROR | 1 |
| REGRESSION_TEST | 1 |
| CORRUPTED_STATE | 1 |
| WRONG_ALERT_OR_PROTOCOL_BEHAVIOR | 1 |
| UNKNOWN | 1 |
| NULL_DEREFERENCE_CRASH (secure heap) | 1 |

**component 分布：**
| Component | Count |
|---|---|
| X509/ASN1 / X509/X509V3/ASN1 | 9 |
| PKEY (RSA/ECC/ED25519/SM2/DSA/ML-DSA) | 6 |
| X509/VERIFY / X509/CRL | 3 |
| BIO/SECURE_HEAP / CRYPTO/MEM_SEC | 2 |
| PKCS12/ASN1 | 2 |
| EVP/AES_GCM / EVP/MAC | 2 |
| CMS / CMS/ED448 | 2 |
| CONF/OPENSSL | 1 |
| RAND_DRBG/EVP_CIPHER_CTX | 1 |
| WPACKET/DER_WRITER/RSA | 1 |
| REQ/ASN1 | 1 |

---

## 3. Issue Table

说明：
- **Main Triggers**: main() 默认执行是否会进入 PoC 触发路径（NO = 需要外部文件 argv[1] 或函数被注释）
- **Self-Contained**: 不需要外部文件即可运行
- **Likely Family**: 当前框架最可能对应的 harness family

| Issue | Title (缩写) | Component | Trigger | Artifact Class | Strict Repr. | Self-Contained | Main Triggers | Has Inputs | Likely Family | Difficulty | Priority |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2630 | Secure heap segfault (small alloc) | BIO/SECURE_HEAP | SEGV | A_ast_ready | false | YES | **NO** (注释掉) | no | secure_heap_small_allocation_oracle (new) | HIGH | P3 |
| 6788 | CRL: multiple CA same subject | CRL/X509 | WRONG_RESULT | B2 | false | no | NO (needs file) | yes | x509_verify_semantic | MEDIUM | P2 |
| 8435 | SM2 invalid signature | PKEY/ECC/SM2 | WRONG_RESULT | B2 | false | no | NO (needs file) | yes | pkey_capability_mismatch_oracle (new) | HIGH | P3 |
| 8980 | EVP_CIPHER_CTX_copy uninit memory | EVP/AES_GCM | NULL_DEREFERENCE_CRASH | A_ast_ready | false | YES | YES | no | crash_sanitizer_oracle | LOW | **P1** |
| 9043 | NULL deref in CSR text output | X509/CSR/ASN1 | NULL_DEREFERENCE_CRASH | C_rag | false | no | NO (needs file) | no | crash_sanitizer_oracle | MEDIUM | P2 |
| 11567 | Semantic bug verifying cert | X509/ASN1 | WRONG_RESULT | B2 | false | no | NO (needs file) | no | x509_verify_semantic | HIGH | P3 |
| 11772 | x509 returns 0 on invalid date | X509/X509V3/ASN1 | WRONG_RESULT | B2 | false | no | NO (needs file) | no | x509_asn1_inner_boundary | HIGH | P3 |
| 13860 | Pubkey output behavior change | X509/X509V3/ASN1 | UNKNOWN | B2 | false | no | NO (needs file) | yes | x509_asn1_inner_boundary | HIGH | P3 |
| 14457 | Self-signed cert verify error 20 | X509/X509V3/ASN1 | WRONG_OUTPUT | B2 | false | no | NO (needs file) | yes | x509_verify_semantic | MEDIUM | P2 |
| 14675 | verify ignores certs after first | X509/VERIFY | WRONG_ALERT | B2 | false | no | NO (needs file) | no | x509_verify_semantic | HIGH | P3 |
| 15899 | RSA modulus segfault (BN uninit) | BN/ASN1 | NULL_DEREFERENCE_CRASH | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | MEDIUM | P2 |
| 16196 | req segfault (BN_print) | REQ/ASN1 | NULL_DEREFERENCE_CRASH | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | MEDIUM | P2 |
| 17715 | DRBG uninitialized cipher_data | RAND_DRBG/EVP | NULL_DEREFERENCE_CRASH | B2 | false | no | NO (needs file) | no | crash_sanitizer_oracle | HIGH | P3 |
| 18168 | WPACKET assertion RSA write | WPACKET/DER/RSA | ASSERTION_FAILURE | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | HIGH | P3 |
| 18659 | CONF_modules_unload after cleanup | CONF/OPENSSL | SEGV | A_ast_ready | false | YES | YES | no | object_state_lifecycle | MEDIUM | **P1** |
| 19524 | ED25519 sign null private key | PKEY/ED25519 | NULL_DEREFERENCE_CRASH | C_rag | false | YES | YES | no | null_deref_dispatch | LOW | **P1** |
| 21935 | RSA 1.1.1 API broken (BN null) | PKEY/RSA | NULL_DEREFERENCE_CRASH | C_rag | false | YES | YES | no | null_deref_dispatch | LOW | **P1** |
| 22388 | X25519/X448 CMS not supported | CMS/X509 | WRONG_RESULT | B2 | false | no | NO (needs file) | yes | pkey_capability_mismatch_oracle (new) | HIGH | P3 |
| 22842 | EVP_MAC_CTX_get_mac_size SIGSEGV | EVP/MAC | NULL_DEREFERENCE_CRASH | C_rag | false | YES | YES | no | object_state_lifecycle | LOW | **P1** |
| 23325 | X509: wrongly rejects cert (CRL IDP) | X509/CRL | WRONG_RESULT | B2 | false | no | NO (needs file) | yes | x509_verify_semantic | HIGH | P3 |
| 26106 | PKCS12 X509_ALGOR_get0 segfault | PKCS12/X509 | NULL_DEREFERENCE_CRASH | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | MEDIUM | P2 |
| 27572 | CMP UTF-8 subject corruption | CMP/ASN1 | WRONG_OUTPUT | B2 | false | no | NO (needs file) | yes | return_code_outlen_semantic | HIGH | P3 |
| 28669 | CRYPTO_secure_used null rwlock | CRYPTO/MEM_SEC | NULL_DEREFERENCE_CRASH | A_ast_ready | false | YES | YES | no | crash_sanitizer_oracle | LOW | **P1** |
| 29418 | x509 -purpose inconsistent result | X509/X509V3 | WRONG_RESULT | B2 | false | no | NO (needs file) | no | x509_verify_semantic | MEDIUM | P2 |
| 29574 | Short cert accepted, corrupts state | X509/X509V3 | CORRUPTED_STATE | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | HIGH | P3 |
| 29645 | BIO_set_data crash | BIO/CONF | NULL_DEREFERENCE_CRASH | C_rag | false | YES | YES | no | object_state_lifecycle | LOW | **P1** |
| 30291 | CMS regression ED448 | CMS/ED448 | REGRESSION_TEST | B2 | false | no | NO (needs file) | yes | pkey_capability_mismatch_oracle (new) | HIGH | P3 |
| 30432 | DSA SHA384/512 verify error | PKEY/DSA | VERIFY_ERROR | B2 | false | no | NO (needs file) | yes | pkey_capability_mismatch_oracle (new) | HIGH | P3 |
| 30581 | PKCS12 PBMAC1 null deref | PKCS12/ASN1 | NULL_DEREFERENCE_CRASH | B2 | false | no | NO (needs file) | yes | crash_sanitizer_oracle | MEDIUM | P2 |
| 30889 | pkey segfault interactive encrypt | PKEY/ML-DSA | SEGV | B2 | false | no | NO (needs file) | no | crash_sanitizer_oracle | HIGH | P3 |

---

## 4. Issue 详细说明

### issue_2630 — 重要特别备注

```
Issue: 2630
Title: Secure heap impl.: segmentation fault in sh_add_to_list for small allocations
Component: BIO/SECURE_HEAP
Critical APIs:
  - CRYPTO_secure_malloc_init
  - BIO_new(BIO_s_secmem())
  - BIO_write
Trigger behavior: SEGV
Strict reproduction: false
main() triggers PoC: NO

*** CRITICAL: poc.c main() 中的两个函数全部被注释掉 ***
    /* example1(); */
    /* example2(); */
    默认执行 main() 只返回 0，不进入任何 PoC 路径。
    必须手动解注释才能进入 example1() 或 example2()。

Migration risk:
  OpenSSL 专属 secure heap (BIO_s_secmem / CRYPTO_secure_malloc_init) 机制。
  mbedTLS 无对应公开 API。大概率 migration_not_applicable。
  即使解注释并在受影响版本上复现，也无 mbedTLS 等价路径。
  建议: migration_not_applicable / no_equivalent_public_api。

Note:
  local_test_result: compiled_and_executed_no_valgrind_error
  只说明 main() 的空壳在当前版本可以运行，不代表漏洞已复现。
```

### issue_8980 — 推荐 P1

```
Issue: 8980
Title: OpenSSL 1.0.2 uninitialized memory in EVP_CIPHER_CTX_copy
Component: EVP/AES_GCM
Critical APIs:
  - EVP_CIPHER_CTX_new
  - EVP_aes_128_gcm
  - EVP_EncryptInit_ex
  - EVP_CIPHER_CTX_copy
Trigger behavior: NULL_DEREFERENCE_CRASH
Artifact class: A_ast_ready
strict_reproduction: false
Self-contained: YES (no external file)
main() triggers PoC: YES (全程序均可执行)

Note:
  poc.c 完整调用 EVP_CIPHER_CTX_copy，测试从未设置 IV/key 的 GCM context 的复制行为。
  mbedTLS 等价路径：mbedtls_cipher_context_copy / mbedtls_cipher_setup。
  harness_family: crash_sanitizer_oracle
  迁移难度：LOW。
```

### issue_18659

```
Issue: 18659
Title: CONF_modules_unload after OPENSSL_cleanup causes segfault
Component: CONF/OPENSSL
Critical APIs:
  - OPENSSL_init_ssl
  - OPENSSL_cleanup
  - CONF_modules_unload
Trigger behavior: SEGV
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES (调用顺序已在 main 中)

Note:
  测试 cleanup 后的 use-after-free / double-free 生命周期语义。
  mbedTLS 等价路径：mbedtls_entropy_free / mbedtls_ctr_drbg_free 调用顺序语义。
  harness_family: object_state_lifecycle
  迁移难度：MEDIUM（需要找合适的对象生命周期 API）。
```

### issue_19524

```
Issue: 19524
Title: ED25519_sign and ED448_sign missing check for private_key
Component: PKEY/ED25519/ED448
Critical APIs:
  - EVP_PKEY_new_raw_public_key (使用 public key 尝试 sign)
  - EVP_MD_CTX_new
  - EVP_DigestSignInit
  - EVP_DigestSign
Trigger behavior: NULL_DEREFERENCE_CRASH
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES

Note:
  使用 public-only key 调用 sign 操作，预期触发 null deref。
  mbedTLS 等价路径：mbedtls_pk_sign 或 EVP 等价 API。
  harness_family: null_deref_dispatch
  迁移难度：LOW。
  但注意：harness 当前以 public key 调用 DigestSign，可能在新版 OpenSSL 中返回错误
  而不是崩溃（已修复）。迁移应以 oracle 而非 crash 为主要信号。
```

### issue_21935

```
Issue: 21935
Title: RSA 1.1.1 API broken in openssl-SNAP-20230831
Component: PKEY/RSA
Critical APIs:
  - RSA_new / RSA_set0_key / EVP_PKEY_assign_RSA
  - EVP_DigestSignInit (with tiny toy RSA key n=3233)
Trigger behavior: NULL_DEREFERENCE_CRASH
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES

Note:
  使用极小玩具 RSA key (n=3233) 测试 DigestSignInit 行为。
  mbedTLS 等价路径：mbedtls_rsa_import / mbedtls_pk_sign。
  harness_family: null_deref_dispatch 或 crash_sanitizer_oracle
  迁移难度：LOW。
```

### issue_22842

```
Issue: 22842
Title: SIGSEGV from EVP_MAC_CTX_get_mac_size()
Component: EVP/MAC
Critical APIs:
  - EVP_MAC_fetch / EVP_MAC_CTX_new
  - EVP_MAC_init (HMAC-SHA256)
  - EVP_MAC_CTX_get_mac_size
Trigger behavior: NULL_DEREFERENCE_CRASH
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES

Note:
  当前 harness 是 RAG seed candidate，EVP_MAC_init 使用 HMAC-SHA256，
  实际上是测试正常初始化路径。原始 bug 是未初始化 algctx 时调用 get_mac_size。
  当前 harness 可能不能触发 NULL deref（因为已调用 init）。
  需要进一步评估 oracle 路径。
  mbedTLS 等价：mbedtls_md_hmac_init / mbedtls_md_get_size。
  harness_family: object_state_lifecycle 或 invalid_parameter_setup_oracle
  迁移难度：LOW。
```

### issue_28669

```
Issue: 28669
Title: NULL rwlock dereference in CRYPTO_secure_used when secure heap not initialized
Component: CRYPTO/MEM_SEC
Critical APIs:
  - CRYPTO_secure_used (called without CRYPTO_secure_malloc_init)
Trigger behavior: NULL_DEREFERENCE_CRASH
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES
local_test_result: segmentation_fault_and_valgrind_invalid_read

Note:
  local_run: false (程序会 segfault)。
  这是唯一 local_run=false 的 issue，segfault 已可在本地观测。
  然而 CRYPTO_secure_used 是 OpenSSL 专属内存管理 API，
  mbedTLS 无直接等价公开 API。
  建议: crash_sanitizer_oracle family，但迁移可能 migration_not_applicable。
  迁移难度：LOW 触发，HIGH 语义投影。
```

### issue_29645

```
Issue: 29645
Title: BIO_set_data() causes crash
Component: BIO/CONF
Critical APIs:
  - BIO_new(BIO_s_mem)
  - BIO_set_data / BIO_get_data
Trigger behavior: NULL_DEREFERENCE_CRASH
strict_reproduction: false
Self-contained: YES
main() triggers PoC: YES

Note:
  RAG seed candidate，当前 harness 测试 BIO_set_data 指针一致性。
  并非严格复现原始崩溃；oracle 当前是指针比较，不是 crash oracle。
  mbedTLS 无直接等价 BIO 对象生命周期 API。
  建议 migration_not_applicable 或需要新 family。
  迁移难度：MEDIUM。
```

---

## 5. Recommended Migration Order

### Priority 1 — 立即可行，适合当前框架

这些 issue 满足：self-contained、main() 直接触发路径、无外部文件依赖、
API 路径清晰、存在潜在 mbedTLS 等价 API。

**issue_8980** — EVP_CIPHER_CTX_copy uninitialized memory
- trigger: GCM cipher context copy without key/IV setup
- family: `crash_sanitizer_oracle`
- mbedTLS target: `mbedtls_cipher_setup` / cipher context copy equivalent
- risk: LOW；原始 bug 在 1.0.2，当前版本已修复；oracle 可能为 safe/safe

**issue_19524** — ED25519 public-key-only sign
- trigger: EVP_DigestSign with public-only ED25519 key
- family: `null_deref_dispatch`
- mbedTLS target: `mbedtls_pk_sign` with public-only context
- risk: LOW-MEDIUM；bug 已修复，oracle 需关注错误返回而非 crash

**issue_21935** — RSA tiny key DigestSignInit
- trigger: RSA_set0_key tiny toy key → EVP_DigestSignInit
- family: `null_deref_dispatch` / `crash_sanitizer_oracle`
- mbedTLS target: `mbedtls_rsa_import` / `mbedtls_pk_sign`
- risk: LOW；玩具 key 在 mbedTLS 可能直接返回错误而不 crash

**issue_22842** — EVP_MAC_CTX_get_mac_size HMAC state
- trigger: EVP_MAC_init → EVP_MAC_CTX_get_mac_size
- family: `object_state_lifecycle` / `invalid_parameter_setup_oracle`
- mbedTLS target: `mbedtls_md_hmac_starts` / `mbedtls_md_get_size`
- risk: LOW；当前 harness 已调用 init，可能 oracle 不触发 null deref

**issue_18659** — CONF_modules_unload after OPENSSL_cleanup
- trigger: OPENSSL_cleanup → CONF_modules_unload
- family: `object_state_lifecycle`
- mbedTLS target: mbedtls init/free sequence ordering
- risk: MEDIUM；OpenSSL-specific cleanup order，mbedTLS 等价语义需评估

### Priority 2 — 可迁移，但需要外部文件或语义投影

**issue_15899** — BN uninit passed to EVP_PKEY_get_bn_param
- has inputs/httpd.crt (but original trigger cert missing)
- family: `crash_sanitizer_oracle`
- mbedTLS target: bignum / RSA parameter extraction
- risk: MEDIUM；需要原始触发证书

**issue_16196** — BN_print NULL deref in req path
- has inputs/test.csr (placeholder)
- family: `crash_sanitizer_oracle`
- mbedTLS target: CSR BN printing equivalent
- risk: MEDIUM

**issue_26106** — PKCS12 X509_ALGOR_get0 NULL deref
- has inputs/placeholder
- family: `crash_sanitizer_oracle`
- mbedTLS target: `mbedtls_pkcs12_parse`
- risk: MEDIUM；需原始 .pk12 文件

**issue_30581** — PKCS12 PBMAC1 salt NULL deref
- has inputs/placeholder
- family: `crash_sanitizer_oracle`
- mbedTLS target: PKCS12 parsing path
- risk: MEDIUM

**issue_14457** — Self-signed cert verify error 20
- has inputs/root.cer (placeholder)
- family: `x509_verify_semantic`
- mbedTLS target: `mbedtls_x509_crt_verify`
- risk: MEDIUM；语义投影问题：X509_STORE 与 mbedTLS 验证上下文差异较大

**issue_29418** — x509 -purpose inconsistent results
- family: `x509_verify_semantic`
- mbedTLS target: `mbedtls_x509_crt_check_key_usage`
- risk: MEDIUM

### Priority 3 — 迁移困难或大概率 migration_not_applicable

**issue_2630** — Secure heap (OpenSSL 专属)
- main() 函数注释掉，默认不触发
- BIO_s_secmem / CRYPTO_secure_malloc_init 无 mbedTLS 等价
- verdict: migration_not_applicable

**issue_28669** — CRYPTO_secure_used null rwlock (OpenSSL 专属)
- CRYPTO_secure_used 无 mbedTLS 等价
- local_run=false (本地可见 segfault)
- verdict: crash observable，但 migration_not_applicable

**issue_8435** — SM2 signature (OpenSSL SM2 专属)
- SM2 is not supported in standard mbedTLS builds
- verdict: migration_not_applicable (无 mbedTLS SM2 等价)

**issue_17715** — DRBG uninitialized cipher_data
- 需要特定 DRBG 内部状态触发，难以构造 harness
- 多步 CLI 路径转换，路径不清晰
- verdict: needs_triage

**issue_22388, 30291** — CMS/X25519/ED448
- CMS 在 mbedTLS 中无直接对应
- verdict: migration_not_applicable

**issue_30432** — DSA SHA384/512 (DSA not in mbedTLS 3.x+)
- mbedTLS 4.x 中 DSA 支持有限
- verdict: migration_not_applicable or triage

**issue_11567, 11772, 13860, 14675, 23325, 29574** — 需要原始触发输入
- 原始输入证书缺失，仅有 placeholder
- 触发路径依赖特定格式错误的证书
- verdict: needs_original_input，短期内难以迁移

---

## 6. Recommended First Issue

### Top 5 推荐迁移候选

**1. issue_8980 — EVP_CIPHER_CTX_copy (首推)**

```
reason: >
  self-contained，无外部文件依赖。poc.c main() 直接调用 EVP_CIPHER_CTX_copy，
  测试 GCM context 在未设置 key/IV 时的 copy 行为。
  API 路径清晰：EVP_CIPHER_CTX_new → EVP_aes_128_gcm →
  EVP_EncryptInit_ex(no key/IV) → EVP_CIPHER_CTX_copy。
  mbedTLS 等价路径：mbedtls_cipher_setup / cipher context state management。
  harness_family: crash_sanitizer_oracle 已有框架支持。
  即使原始 bug 在 1.0.2 已修复，safe/safe 结果也是有效迁移结论。

likely target library: mbedtls
likely target API: mbedtls_cipher_setup / mbedtls_cipher_clone (if available)
likely harness_family: crash_sanitizer_oracle
risk: LOW；原始版本已修复，预期 safe/safe 或 triage 结果
```

**2. issue_19524 — ED25519 public-key-only sign**

```
reason: >
  self-contained，无外部文件依赖。以 public-only ED25519 key 调用 DigestSign，
  测试 missing private key check 行为。API 路径清晰。
  mbedTLS 等价：mbedtls_pk_sign with EVP_PKEY_ED25519 equivalent。
  harness_family: null_deref_dispatch 已有框架支持。

likely target library: mbedtls
likely target API: mbedtls_pk_sign (with public-only key context)
likely harness_family: null_deref_dispatch
risk: LOW-MEDIUM；需要构造 mbedTLS public-only 上下文并调用 sign
```

**3. issue_21935 — RSA tiny key DigestSignInit**

```
reason: >
  self-contained，无外部文件依赖。玩具 RSA key (n=3233) 场景简单可控。
  测试 RSA_set0_key + EVP_PKEY_assign_RSA + EVP_DigestSignInit 的完整链路。
  mbedTLS 等价：mbedtls_rsa_import + mbedtls_rsa_check_privkey + mbedtls_pk_sign。

likely target library: mbedtls
likely target API: mbedtls_rsa_import / mbedtls_pk_sign
likely harness_family: crash_sanitizer_oracle / null_deref_dispatch
risk: LOW；玩具 key 在 mbedTLS 可能直接被参数验证拒绝
```

**4. issue_22842 — EVP_MAC_CTX_get_mac_size**

```
reason: >
  self-contained，无外部文件依赖。HMAC-SHA256 MAC context 状态管理。
  EVP_MAC_fetch → EVP_MAC_CTX_new → EVP_MAC_init → get_mac_size。
  mbedTLS 等价：mbedtls_md_hmac_starts / mbedtls_md_get_size。

likely target library: mbedtls
likely target API: mbedtls_md_hmac_starts / mbedtls_md_get_size
likely harness_family: object_state_lifecycle / invalid_parameter_setup_oracle
risk: LOW；当前 harness 可能已在正常路径运行，oracle 需调整
```

**5. issue_18659 — CONF_modules_unload lifecycle**

```
reason: >
  self-contained，无外部文件依赖。测试 cleanup 后再调用的生命周期语义。
  harness_family: object_state_lifecycle 已有框架支持。
  mbedTLS 等价需评估 mbedtls_entropy/ctr_drbg cleanup 顺序语义。

likely target library: mbedtls
likely target API: mbedtls_entropy_free / mbedtls_ctr_drbg_free ordering
likely harness_family: object_state_lifecycle
risk: MEDIUM；OpenSSL CONF cleanup 语义与 mbedTLS entropy cleanup 差异较大
```

---

## 7. Migration Framework Notes

### 已有可复用 harness family（来自 AGENTS.md）

| Family | 适用 OpenSSL issues |
|---|---|
| `crash_sanitizer_oracle` | 8980, 19524, 21935, 15899, 16196, 26106, 30581 |
| `null_deref_dispatch` | 19524, 21935, 28669 |
| `object_state_lifecycle` | 22842, 18659, 29645 |
| `invalid_parameter_setup_oracle` | 22842 |
| `x509_asn1_inner_boundary` | 11772, 13860 |
| `der_pointer_consumption` | 29574 |

### 可能需要新增的 family（OpenSSL 专属）

| Family | 适用场景 | Notes |
|---|---|---|
| `secure_heap_small_allocation_oracle` | issue_2630, 28669 | OpenSSL 专属，mbedTLS 无对应 API |
| `pkey_capability_mismatch_oracle` | 8435, 22388, 30291, 30432 | 算法支持差异（SM2, X25519-CMS, DSA-SHA512, ED448-CMS） |
| `x509_verify_semantic` | 6788, 14457, 14675, 23325, 29418 | X.509 验证语义语言层面的差异 |
| `openssl_cli_semantic_oracle` | 17715, 27572 | CLI 行为迁移，极难适配 C API |

### 禁止行为提醒

- 不要把 `strict_reproduction=false` 写成已严格复现漏洞
- 不要把 `compiled_and_executed_no_valgrind_error` 写成漏洞已观测
- issue_2630 main() 函数注释掉，不要写成默认触发 PoC
- 迁移决策必须基于 vulnerability-path suitability，不能只看 API 名称相似度
- 不要为 migration_not_applicable 的 issue 强行生成 migrated_safe 或 migrated_bug_candidate

---

*文档生成时间: 2026-05-31，基于 datasets/openssl/poc_artifacts/ 下 30 个 issue 的 metadata.json、poc.c、README.md 静态分析。*
