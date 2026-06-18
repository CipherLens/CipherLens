# Crypto Library Oracle Gap Analysis

本轮目标是把 CAT 的 oracle 分层思想迁移到密码学库 API 测试，而不是继续扩大 fuzz 数量。这里不引入 RPKI 仓库、ROA、Manifest、CRL、TAL、RRDP 或 rsync 逻辑，只保留“多层 oracle + 保守分类”的思想。

## 已有能力

- execution/sanitizer：现有 runner 和若干 campaign 已能记录 ASAN、UBSAN、crash、timeout 等程序级信号。
- parser：已有 DER、X.509、ASN.1、PKCS、CAT-inspired seed enrichment 等 parser 相关结果，但 accept/reject 差异仍需要 API contract 解释。
- roundtrip：已有 BIGNUM / partial PKCS roundtrip/metamorphic baseline，可区分 success、mismatch、normal reject、unsupported。
- crypto semantic：已有 AEAD encrypt/decrypt、MAC、digest 等部分语义不变量测试。
- lifecycle：已有 MAC/Digest lifecycle、AEAD lifecycle，以及 secure heap lifecycle 相关候选记录。
- differential：已有部分跨库比较和 app-level / low-level 差异观察，但尚未统一进入一个分类器。

## 主要缺口

- coverage-guided feedback 尚未与 oracle 联动：当前结果更像阶段性 case/run 分类，尚未把 oracle 命中反向用于 mutation priority。
- negative control 不够系统化：modified tag、modified signature、malformed DER 等应统一进入 negative_control_oracle，而不是散落在各 family。
- API contract 描述不够结构化：很多差异需要先判断“目标 API 是否承诺 full consumption / canonical export / valid state query”。
- cross-version differential 还未统一进入分类器：跨版本差异默认只能是 observation，升级需要负例对照、合同证据和安全影响说明。

## 为什么下一步应做 oracle-first optimization

盲目扩大 fuzz 数量会产生更多 normal reject、unsupported API 和 invalid contract 噪声。当前更需要先把结果分类层稳定下来：什么是 crash candidate，什么只是 semantic observation，什么需要 app-level control，什么是 expected negative control。只有 oracle taxonomy 稳定后，后续 campaign 才能把算力集中在可解释、可复现、可升级的行为上。
