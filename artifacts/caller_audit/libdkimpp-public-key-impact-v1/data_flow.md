# libdkim++ 公钥解析生产数据流审计

## 审计范围与标记

- `confirmed`：固定 commit `9defa162eebc644b006b7a51e92162640a810ee9` 的源码或现有动态证据直接支持。
- `inferred`：由已确认机制推导，但尚未在所述集成边界复现。
- `unproven`：缺少足够证据，不得当作安全影响报告。

本文件只描述生产数据流和数据用途。当前结论仍是 `production_reachable_candidate`，不是已确认漏洞。

## 完整生产链

```text
RFC 5322 message
  -> Validatory constructor parses message and collects DKIM-Signature headers
  -> GetSignature: Signature::Parse + CheckBodyHash
  -> selector + "._domainkey." + signing domain
  -> CustomDNSResolver(query, result, data) OR Resolver::GetTXT(query, result)
  -> DNS TXT character-strings concatenated into std::string publicKey
  -> PublicKey::Parse(publicKey)
  -> TagList::Parse -> p= TagListEntry
  -> remove whitespace from p= value
  -> Base64_Decode(p=)
  -> d2i_PUBKEY(nullptr, &cursor, decoded_size)
       [missing: cursor == decoded_begin + decoded_size]
  -> EVP_PKEY type check -> EVP_PKEY_get1_RSA
  -> CheckSignature key-record constraints and header canonicalization/hash
  -> RSA_verify(..., pub.GetRSAPublicKey())
  -> success, PermanentError, or TemporaryError returned to the caller
```

### 1. 邮件和查询名

`confirmed`：`Validatory` 构造函数解析邮件并收集 `DKIM-Signature` 或 ARC message-signature 头；参考 `src/Validatory.cpp:46-69`。

`confirmed`：典型调用顺序由 bundled tool 展示为：

1. `mail.GetSignature(i, sig)`；
2. `mail.GetPublicKey(sig, pub)`；
3. `mail.CheckSignature(*i, sig, pub)`。

参考 `tools/src/main.cpp:170-194`。`GetSignature` 会先解析签名并检查 body hash，之后才查询公钥，参考 `src/Validatory.cpp:75-85`。

`confirmed`：DNS 名称由 `s=` 和 `d=` 组成：

```cpp
std::string query = sig.GetSelector() + "._domainkey." + sig.GetDomain();
```

参考 `src/Validatory.cpp:92-99`。

### 2. DNS TXT 获取

`confirmed`：调用者可以设置公开的 `CustomDNSResolver` 回调；未设置时调用 `DKIM::Util::Resolver().GetTXT`。两条路径都向局部变量 `std::string publicKey` 写入记录文本，参考 `src/Validatory.hpp:68-69`、`src/Validatory.cpp:97-112`。

`confirmed`：默认 resolver 使用 `res_nquery`/`res_query` 请求 `T_TXT`，并把每个 TXT RR 的 character-string 片段追加到同一个 `result`，参考 `src/Resolver.cpp:64-73,117-164`。

`confirmed`：`NO_DATA`、`HOST_NOT_FOUND`、`NO_RECOVERY` 被映射为成功查询但空结果，随后 `GetPublicKey` 抛出 `PermanentError`；`TRY_AGAIN` 类错误返回 `false` 并变成 `TemporaryError`，参考 `src/Resolver.cpp:75-92`、`src/Validatory.cpp:100-118`。

`inferred`：`CustomDNSResolver` 是真实调用者最可能插入 DNS cache、观测日志或测试数据的位置，但本轮没有发现公开下游调用证据。

### 3. TXT tag-list 和 `p=`

`confirmed`：`PublicKey::Parse` 调用 `m_tagList.Parse(signature)`；`TagList` 保存 tag 名到 `TagListEntry` 的 map，而不是保存原始记录的字节级副本。tag 顺序、分隔格式和外围空白不会保留，参考 `src/PublicKey.cpp:53-55`、`src/TagList.cpp:97-201`。

`confirmed`：`p=` 必须存在；空 `p=` 立即作为 revoked key 抛出 `PermanentError`，参考 `src/PublicKey.cpp:105-111`。这与 [RFC 6376 §3.6.1](https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1) 对空 `p=` 的定义一致。

`confirmed`：`p=` 的解析值仍在私有 `m_tagList` 中，但没有公开 getter，后续验签也不再读取该原始值。函数另建局部 `ptmp` 并删除所有空白，参考 `src/PublicKey.hpp:76-86`、`src/PublicKey.cpp:113-120`。

### 4. Base64 和 DER/SPKI

`confirmed`：`Base64_Decode` 使用 OpenSSL base64 BIO，把输出收集为局部 `std::string tmp`，参考 `src/Base64.cpp:28-46`。

`confirmed`：RSA 路径把 `tmp.c_str()` 赋给可前移的 `tmp2`，然后调用：

```cpp
EVP_PKEY* publicKey = d2i_PUBKEY(nullptr, &tmp2, tmp.size());
```

参考 `src/PublicKey.cpp:118-125`。

`confirmed`：原始版本只检查 `publicKey != nullptr`，没有比较 `tmp2` 与输入末尾。因此，成功解析一个 SPKI 前缀后留下的尾随字节不会导致调用者拒绝。

`confirmed`：现有动态证据表明 canonical SPKI、`SPKI||0500`、`SPKI||3000`、`SPKI||020100` 均被原始版本接受；三种变体重新序列化为 canonical SPKI、与原公钥相等且能验证同一签名。参考 `../libdkimpp-public-key-v1/v0.1/dynamic_evidence.yaml`。

`confirmed`：fix control 保存 `tmp_end` 并要求 `tmp2 == tmp_end`；canonical 仍通过，三种变体均拒绝。参考 `caller_audit/fix_controls/libdkimpp_public_key_full_consumption.patch` 和上述动态证据。

### 5. RSA 对象和验签

`confirmed`：解析出的 `EVP_PKEY` 必须是 RSA/RSA2；随后通过 `EVP_PKEY_get1_RSA` 保存到 `m_publicKeyRSA`，临时 `EVP_PKEY` 被释放，参考 `src/PublicKey.cpp:127-139`。

`confirmed`：`CheckSignature` 先执行 key-record 约束：

- `h=` 限制允许的 digest algorithm；
- 签名算法必须与 key type 一致；
- `t=s` 时 `d=` 必须与 identity domain 精确一致。

参考 `src/Validatory.cpp:172-189`。

`confirmed`：完成签名头 canonicalization 和 digest 后，RSA 路径调用 `RSA_verify`；返回值不是 1 则抛出 `PermanentError(..., AR_FAIL)`，参考 `src/Validatory.cpp:191-270`。

`confirmed`：尾随字节不会进入 `RSA_verify`，也不会改变其 RSA key 参数；它们只影响 DER 输入表示及严格解析器是否接受。

## 数据生命周期

| 数据 | 存活范围/表示 | 后续用途 | 状态 |
|---|---|---|---|
| DNS query name | `selector._domainkey.domain` 局部字符串 | resolver lookup；调用者可在 callback 中缓存 | `confirmed` |
| 原始 DNS TXT 结果 | `Validatory::GetPublicKey` 局部 `publicKey` | 传给 `PublicKey::Parse` 后销毁 | `confirmed` |
| tag-list 语义值 | 私有 `PublicKey::m_tagList` | `Parse` 内读取；原始格式不保留 | `confirmed` |
| `p=` 文本 | 私有 tag entry 加局部 `ptmp` | 去空白、Base64 解码；后续验签不读取文本 | `confirmed` |
| decoded DER | `Parse` 局部 `tmp` | `d2i_PUBKEY`；函数返回后销毁 | `confirmed` |
| parsed key | `RSA* m_publicKeyRSA` | key constraints 和 `RSA_verify` | `confirmed` |
| DKIM result | exception/success control flow | 由外部调用者解释；bundled tool 仅打印 | `confirmed` |
| DMARC/filter result | 不在已审计源码中形成 | 依赖真实下游 | `unproven` |

## 安全相关用途搜索结果

搜索范围为固定 commit 的 `src/`、`tools/`、`tests/`、`README.md`，关键词和符号包括 `PublicKey`、`GetTXT`、`p=`、`cache`、`hash`、`fingerprint`、`equal`、`dedup`、`trust`、`whitelist`、`blacklist`、`policy`、`log`、`audit`、`rotate`、`revoke`。

| 类别 | 结论 | 状态 | 证据/限制 |
|---|---|---|---|
| cache | 没有 DNS TXT 或公钥 cache | `confirmed` | `headerCache` 仅是 `CheckSignature` 的单封邮件头 map，见 `src/Validatory.cpp:208-237` |
| hash/fingerprint | 没有以 raw TXT、`p=`、decoded DER 或 RSA key 建身份指纹 | `confirmed` | 出现的 digest 是 body/header signature digest，不是 key identity |
| equality/dedup | 没有公钥 equality 或 dedup | `confirmed` | 现有 `memcmp` 只比较 body hash |
| trust/allowlist/blocklist | 没有按 key 或 raw record 的信任名单 | `confirmed` | key-record 自带约束不等于外部信任名单 |
| policy | `h=`、`k=`、`t=s` 和 `p=` empty 会影响验证 | `confirmed` | 与尾随 DER 表示没有单独身份绑定 |
| service type | `s=` 被解析并保存 | `confirmed` | 在固定 commit 的 `Validatory` 中未发现消费点 |
| testing flag | `t=y` 可由 `SoftFail()` 暴露 | `confirmed` | bundled tool 在异常时打印 `SOFT`；真实下游处置未知 |
| logging/auditing | library 不记录 raw DNS/key；tool 打印文件、域、selector、结果和错误 | `confirmed` | 不打印 `p=`、DER 或 key fingerprint |
| key rotation | 没有 rotation 状态；每个签名在示例循环中重新查 key | `confirmed` | caller 自己实现的 resolver cache 仍可能存在，但未找到 |
| revocation | 仅实现 empty `p=` revocation | `confirmed` | 没有 raw/canonical fingerprint revocation store |
| DMARC/filter/mail acceptance | 固定源码不形成最终邮件政策决定 | `confirmed` | README 声称支持/用于 DMARC 场景，但公开集成调用点不可见，具体影响 `unproven` |

## 与安全影响的边界

`confirmed`：控制自己域名、DNS key record 和匹配私钥的发件人本来就能发布 canonical SPKI 并取得有效 DKIM。当前变体没有展示额外权限。

`inferred`：严格解析实现与 libdkim++ 可能对同一 DNS 记录产生 accept/reject 分歧。Go `crypto/x509.ParsePKIXPublicKey` 的官方源码显式拒绝 ASN.1 后的 trailing data，可作为第一比较实现：[Go x509 source](https://go.dev/src/crypto/x509/x509.go#L72)。同一 corpus 尚未在本阶段跨实现执行。

`unproven`：只有当真实调用者把 raw record 与 parsed key 分别用于 cache、撤销、信任或政策，或把 libdkim++ 的 DKIM pass 映射为攻击者原本得不到的 DMARC/filter 权限时，才可能升级为安全影响。

## 可追溯源码链接

- [Validatory.cpp at fixed commit](https://github.com/halon/libdkimpp/blob/9defa162eebc644b006b7a51e92162640a810ee9/src/Validatory.cpp)
- [PublicKey.cpp at fixed commit](https://github.com/halon/libdkimpp/blob/9defa162eebc644b006b7a51e92162640a810ee9/src/PublicKey.cpp)
- [Resolver.cpp at fixed commit](https://github.com/halon/libdkimpp/blob/9defa162eebc644b006b7a51e92162640a810ee9/src/Resolver.cpp)
- [TagList.cpp at fixed commit](https://github.com/halon/libdkimpp/blob/9defa162eebc644b006b7a51e92162640a810ee9/src/TagList.cpp)
- [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376.html)

