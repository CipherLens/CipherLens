# libdkim++ 公钥解析影响实验计划

## 决策目标

本计划不预设漏洞结论。目标是依次回答三个问题：

1. 是否存在可复现的跨实现 accept/reject 差异？
2. “原始表示不同、解析公钥相同”是否进入真实 cache、身份、撤销或政策边界？
3. 在完整邮件链中，差异是否改变攻击者原本得不到的 DKIM/DMARC/过滤结果？

若只能回答第 1 项，应维持“解析严格性/互操作性候选”；若第 2、3 项没有真实调用者证据，不得升级为安全漏洞。

## 固定环境与工作区纪律

- libdkim++：`9defa162eebc644b006b7a51e92162640a810ee9`。
- OpenSSL：`~/workplace/CryptoPoc/clean_sources/openssl-3.5.5`，运行时记录 `OpenSSL 3.5.5 27 Jan 2026`。
- 编译器：`clang++`，Debug，保留 `-fsanitize=address,undefined -fno-omit-frame-pointer`。
- 运行环境：`ASAN_OPTIONS=detect_leaks=1:abort_on_error=1`，`UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1`。
- 外部原始工作区 `~/workplace/third_party/caller-audit/libdkimpp` 只读，不应用 patch、不生成构建文件。
- baseline 和 fix-control 均由 `caller_audit.worktree` 建立独立 worktree；实验性源码修改也必须放在独立 worktree。
- build、二进制、sanitizer 大日志放在 `/tmp/cipherlens-libdkimpp-impact-v1/` 或 gitignored build root，不写入本产物目录。
- 只提交小型 source、fixture、摘要 YAML/JSONL；不提交私钥、构建目录、二进制或大日志。
- 每次仓库文件修改后运行现有 9 项测试；测试命令见“回归与验收”。

## 共享 corpus

所有实验使用同一把临时 2048-bit RSA key、同一封确定性邮件、同一 `DKIM-Signature` 和同一 selector/domain。私钥只用于生成本地 fixture，不进入提交；需要提交时改为公开测试私钥并明确标注非秘密。

DNS 记录矩阵：

| case | decoded `p=` bytes | baseline expectation | fix expectation |
|---|---|---|---|
| `canonical` | canonical DER SPKI | accept | accept |
| `tail_0500` | `SPKI || 05 00` | accept | reject |
| `tail_3000` | `SPKI || 30 00` | accept | reject |
| `tail_020100` | `SPKI || 02 01 00` | accept | reject |
| `invalid_signature` | canonical SPKI, modified `b=` | reject at RSA_verify | reject at RSA_verify |
| `different_key` | canonical SPKI for a different RSA key | reject at RSA_verify | reject at RSA_verify |
| `revoked_empty_p` | empty `p=` | reject as revoked | reject as revoked |
| `invalid_der` | non-SPKI bytes | reject at key parse | reject at key parse |

每个 case 记录：raw TXT、`p=` 文本、decoded DER、consumed length（可用时）、canonical SPKI、RSA modulus/exponent digest、signature result、error class、ASan/UBSan marker。

## 实验 1：跨实现 accept/reject 差异

### 1A. 解析器级矩阵

比较对象：

1. libdkim++ baseline，固定 commit 和 OpenSSL 3.5.5；
2. libdkim++ full-consumption fix control；
3. Go standard library `crypto/x509.ParsePKIXPublicKey`；其官方源码显式拒绝 trailing data：[source](https://go.dev/src/crypto/x509/x509.go#L72)；
4. 一个完整 DKIM 比较器，优先 `emersion/go-msgauth`，因为它同时提供 DKIM/DMARC 能力；实现前固定 commit 并审计其 RSA key parse 调用；
5. 可选第二独立实现 `trusteddomainproject/OpenDKIM`；只有在能注入确定性 DNS 答案且构建成本可控时加入。

`confirmed` 的当前基础：libdkim++ baseline/fix 的四个主要 case 已有动态证据。`inferred`：Go 严格 parser 会拒绝三种 tail。跨实现相同 corpus 尚未运行。

步骤：

1. 从同一 canonical SPKI 生成四种 decoded input 和 DNS `p=`。
2. 每个实现只做公钥解析并输出统一 JSONL：`implementation`, `revision`, `case`, `accepted`, `consumed_len`, `canonical_spki_sha256`, `key_equal`, `error`。
3. 对接受 case 重新序列化并比较 canonical SPKI；不能重序列化的实现比较 modulus/exponent。
4. 确认 comparator 没有先修改或截断输入；否则记录 normalization layer。
5. 对所有 C/C++ 实现启用 ASan/UBSan。

主要 oracle：

- `parser_split=true` 当至少一个实现接受且至少一个实现拒绝相同 decoded bytes；
- `same_key=true` 仅当接受者的 canonical SPKI 或 RSA `(n,e)` 全部一致；
- 任何 crash/sanitizer 报告单独分类，不由 nonzero exit 推断。

解释门槛：

- 只出现 parser split：互操作性/一致性证据；
- parser split 加同一有效签名结果分歧：进入实验 3；
- 不得仅因严格实现拒绝而声明 libdkim++ 有安全漏洞。

### 1B. DKIM 验签级矩阵

使用 comparator 的自定义 DNS hook 返回完整 TXT 记录，验证同一 `.eml`。统一输出：

```json
{"implementation":"...","case":"tail_0500","dns_key_parse":"accept|reject","dkim":"pass|fail|temperror|permerror","reason":"..."}
```

负控制 `invalid_signature` 和 `different_key` 必须在所有实现中失败；若它们通过，先停止并修正 fixture/harness。

## 实验 2：原始表示与 cache/去重/撤销/政策

### 2A. 身份层矩阵

对四个主要 case 计算并输出：

- `raw_txt_sha256`；
- `normalized_p_text_sha256`；
- `decoded_der_sha256`；
- `canonical_spki_sha256`；
- `rsa_ne_sha256`。

预期：前三者对 tail 不同，后两者相同。该实验确认“表示分裂”，不确认安全影响。

### 2B. 真实 caller 优先、模型后置

执行顺序：

1. 若后续找到真实 `CustomDNSResolver` 或验证调用者，先审计其 cache key、value、TTL、negative caching、日志、fingerprint、allow/block/revocation 和 key rotation。
2. 仅在调用者源码表明 raw/canonical 两种身份确实分离时，为该调用者建独立 worktree 和最小集成测试。
3. 若仍没有真实 caller，只允许实现一个明确命名为 `synthetic_representation_model` 的小模型，用来验证传播条件；结果必须保持 `unproven`。

需要分别建模的 key 策略：

| identity | canonical/tail relationship | 可能结果 |
|---|---|---|
| DNS query name (`selector,domain`) | same | 同一 entry 被替换，不形成 key identity bypass |
| raw TXT | different | cache/dedup split；是否安全相关取决于 caller |
| normalized `p=` text | different | 同上 |
| decoded DER hash | different | raw-fingerprint block/revocation 可能 miss |
| canonical SPKI hash | same | 正确合并等价 key |
| RSA `(n,e)` | same | 正确合并等价 key |

撤销/黑名单正向 oracle 仅在真实 caller 存在时有效：canonical 被拒绝、tail fingerprint miss、baseline 验签通过、fix-control 拒绝 tail。RFC empty `p=` 必须保留为负控制，并确认 tail 技术不能把 empty `p=` 变成有效 key。

停止条件：没有真实 caller 时，不扩展成大规模 cache fuzzing，不把 synthetic model 写成漏洞 PoC。

## 实验 3：完整邮件验证、DMARC 和过滤结果

### 3A. libdkim++ 完整生产 API 链

拟建最小 harness，但须在本轮审计汇报获准后实现：

1. 读取确定性 `.eml`；
2. 构造 `DKIM::Validatory`；
3. 安装 in-memory `CustomDNSResolver`，按 case 返回 TXT；
4. 调用 `GetSignature`、`GetPublicKey`、`CheckSignature`；
5. 输出 body hash、query name、key parse、DKIM result、exception class、AuthenticationResult；
6. baseline 与 fix-control 使用同一二进制源码和 fixture 分别构建。

预期：baseline 的 canonical/tails 均 DKIM pass；fix 的 canonical pass、tails key parse permerror。`invalid_signature` 和 `different_key` 在两侧均为 `AR_FAIL`。

### 3B. DMARC 传播模型

构造 `RFC5322.From` 与 DKIM `d=` 对齐、SPF 固定为 fail/none 的消息，使 DKIM 成为唯一对齐路径。优先使用 version-pinned `emersion/go-msgauth` 或另一独立 DMARC evaluator，不在 libdkim++ 内伪造“原生 DMARC”。

记录：`dkim_result`, `dkim_aligned`, `spf_result`, `dmarc_result`, `policy`, `disposition`。

判定：

- 如果 baseline DKIM pass 导致 DMARC pass，而 strict/fix 导致 DMARC fail，标记 `propagation_confirmed`；
- 若没有真实下游政策，这仍是合成传播结果，安全影响保持 `unproven`；
- 只有真实系统据此放行攻击者原本无法用 canonical 记录取得的邮件，才进入漏洞升级评估。

### 3C. 过滤/放行政策

仅保留两个透明规则作为观测器：

- `DKIM aligned pass -> accept`；
- `otherwise -> quarantine/reject`。

模型必须同时运行 canonical control。由于控制 DNS 和私钥的发件人可用 canonical 获得 `accept`，tail 导致的相同结果通常不构成额外权限。这一“无增益”检查是必需 oracle，不是附注。

## 结果分类

| 结果 | 分类 |
|---|---|
| baseline/fix parser split，无下游变化 | `confirmed parser strictness candidate` |
| 跨实现 DKIM split，但攻击者可用 canonical 等价取得 pass | `confirmed interoperability difference; security impact unproven` |
| synthetic DMARC/filter flip，无真实 caller | `confirmed propagation model; security impact unproven` |
| 真实 caller raw fingerprint/cache 分裂，但无安全收益 | `caller behavior confirmed; vulnerability unproven` |
| 真实 caller 的 trust/revocation/policy 被绕过，且 canonical 不可获得同等收益 | 进入漏洞候选复核，仍需威胁模型和负控制 |
| victim-domain pass 无需私钥/DNS 权限 | 高优先级安全影响，但当前无任何证据 |

## 回归与验收

每次仓库文件修改后运行：

```bash
LIBDKIMPP_ROOT="$HOME/workplace/third_party/caller-audit/libdkimpp" \
PYTHONPATH=. python3 -m unittest \
  tests.test_caller_audit_v0_1 \
  tests.test_der_spki_pipeline \
  tests.test_fix_control_patches \
  tests.test_libdkimpp_fix_control
```

该集合当前包含 9 个 test methods。验收还包括：

```bash
git status --short
git diff --check
python3 -c 'import json,sys; [json.loads(x) for x in open(sys.argv[1]) if x.strip()]' artifacts/caller_audit/libdkimpp-public-key-impact-v1/downstream_candidates.jsonl
```

注意：`json.tool` 不能直接验证多对象 JSONL；实际实现应逐行解析。可使用小型只读校验命令逐行 `json.loads`，但不生成新文件。

## 本阶段明确不做

- 不实现影响 Harness；
- 不修改外部 libdkim++ 原始工作区；
- 不运行大规模 fuzzing；
- 不把 parser differential、synthetic cache 或 synthetic DMARC 结果直接写成漏洞；
- 不提交 build、二进制、私钥或大日志。

