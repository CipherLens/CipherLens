# Lua Application Search Summary for MAC Lifecycle Impact

## Scope

This search targets real Lua application use of zhaozg/lua-openssl style MAC context APIs such as `openssl.mac.ctx`, `mac.ctx`, `ctx:update(...)`, and `ctx:final(...)`.

The goal is to determine whether the already reproduced OpenSSL CMAC lifecycle behavior has a real application-level impact path in Lua code.

## Query Results

Successful queries: 7

|name|query|stdout_bytes|
|---|---|---|
|01_mac_ctx_language_lua|mac.ctx language:Lua|932|
|02_openssl_mac_language_lua|"openssl.mac" language:Lua|18984|
|03_require_openssl_language_lua|"require(\"openssl\")" language:Lua|17055|
|05_openssl_final_update_language_lua|"openssl" "final(" "update(" language:Lua|17144|
|06_cmac_openssl_language_lua|"CMAC" "openssl" language:Lua|9565|
|07_hmac_openssl_final_language_lua|"HMAC" "openssl" "final" language:Lua|17663|
|04c_update_final_language_lua_broad|update final language:Lua|14606|

Failed queries: 2

|name|query|error|
|---|---|---|
|04_update_final_language_lua|":update(" ":final(" language:Lua|HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL Unknown language: "Lua\"" (https://api.github.com/search/code?page=1&per_page=50&q=%22%3A%22update%28%5C%22+%5C%22%3Afi|
|04b_update_final_language_lua_fixed|:update :final language:Lua|HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL Unknown language: "Lua\"" (https://api.github.com/search/code?page=1&per_page=50&q=%3A%22update+%3Afinal+language%3ALua|

Notes:

- The original `":update(" ":final(" language:Lua` query failed with GitHub code-search parser errors.
- A broad fallback query `update final language:Lua` succeeded and was included in ranking.
- Direct `mac.ctx` hits were only lua-openssl's own test or vendored test copies, not real application code.

`01_mac_ctx_language_lua.json` direct hits (3):
- `zhaozg/lua-openssl` `test/2.mac.lua`: https://github.com/zhaozg/lua-openssl/blob/eae55e1f7969a802d79bac5e198e7169f5f938f8/test/2.mac.lua
- `huahua132/skynet_fly` `3rd/lua-openssl/test/2.mac.lua`: https://github.com/huahua132/skynet_fly/blob/8d09dfdbf29612dbcc6b3acdcbede80434add9ef/3rd/lua-openssl/test/2.mac.lua
- `iiAlladin/lua-openssl-quik` `test/2.mac.lua`: https://github.com/iiAlladin/lua-openssl-quik/blob/996549dfe3944f50e5946e51d983b7f58f4187bb/test/2.mac.lua

`require_openssl_mac_ctx.json` direct hits (3):
- `zhaozg/lua-openssl` `test/2.mac.lua`: https://github.com/zhaozg/lua-openssl/blob/eae55e1f7969a802d79bac5e198e7169f5f938f8/test/2.mac.lua
- `huahua132/skynet_fly` `3rd/lua-openssl/test/2.mac.lua`: https://github.com/huahua132/skynet_fly/blob/8d09dfdbf29612dbcc6b3acdcbede80434add9ef/3rd/lua-openssl/test/2.mac.lua
- `iiAlladin/lua-openssl-quik` `test/2.mac.lua`: https://github.com/iiAlladin/lua-openssl-quik/blob/996549dfe3944f50e5946e51d983b7f58f4187bb/test/2.mac.lua


## Candidate Counts

- Ranked candidates after filtering: 50 shown in `lua_app_search_ranked.txt` (Top 50 output).
- Downloaded candidate files: 20 from Top 20.
- Assessment ratings: {'low': 17, 'noise': 3}.

## Top 10 Ranked Candidates

|rank|score|repo|path|hits|
|---|---|---|---|---|
|1|30|Kong/lua-resty-aws|src/resty/aws/request/signatures/utils.lua|high:sign,high:signature,high:request|
|2|30|haproxytech/haproxy-lua-oauth|lib/jwtverify.lua|high:auth,high:verify,high:jwt|
|3|20|apache/apisix|apisix/plugins/jwt-auth/parser.lua|high:auth,high:jwt|
|4|15|SGU-K22C4/CNLTHD26K1_Nhom9|docker/kong/plugins/jwt-auth/handler.lua|high:auth,high:jwt,low:doc|
|5|14|Kong/kong|kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|
|6|14|Mohammed-Kamel-Frost-32/https-github.com-Kong-kong.|kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|
|7|14|epam/edp-ddm-kong|kong/kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|
|8|14|gridgentoo/kong|kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|
|9|14|inclavare-containers/kong_coco|kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|
|10|14|mbarnes-code/expert-dollop|infrastructure/kong/kong/plugins/hmac-auth/access.lua|high:auth,medium:hmac|

## Top 20 Static Assessment

|rank|repo|file|target_mac_ctx|post_final|rating|notes|
|---|---|---|---|---|---|---|
|1|Kong/lua-resty-aws|src/resty/aws/request/signatures/utils.lua|false|false|low|uses lua-resty-openssl hmac one-shot; uses lua-openssl hmac, not openssl.mac.ctx; generic final/update text exists but not target mac ctx; n|
|2|haproxytech/haproxy-lua-oauth|lib/jwtverify.lua|false|false|low|uses lua-openssl hmac, not openssl.mac.ctx; uses digest, not MAC ctx; JWT/security context; generic final/update text exists but not target |
|3|apache/apisix|apisix/plugins/jwt-auth/parser.lua|false|false|low|uses lua-resty-openssl mac, not zhaozg lua-openssl mac.ctx; uses digest, not MAC ctx; JWT/security context; generic final/update text exists|
|4|SGU-K22C4/CNLTHD26K1_Nhom9|docker/kong/plugins/jwt-auth/handler.lua|false|false|low|uses lua-resty-openssl hmac one-shot; uses lua-openssl hmac, not openssl.mac.ctx; JWT/security context; doc/test/example path; no direct tar|
|5|Kong/kong|kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl mac, not zhaozg lua-openssl mac.ctx; generic final/update text exists but not target mac ctx; no direct target openss|
|6|Mohammed-Kamel-Frost-32/https-github.com-Kong-kong.|kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl mac, not zhaozg lua-openssl mac.ctx; generic final/update text exists but not target mac ctx; no direct target openss|
|7|epam/edp-ddm-kong|kong/kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl hmac one-shot; uses lua-openssl hmac, not openssl.mac.ctx; generic final/update text exists but not target mac ctx; n|
|8|gridgentoo/kong|kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl hmac one-shot; uses lua-openssl hmac, not openssl.mac.ctx; generic final/update text exists but not target mac ctx; n|
|9|inclavare-containers/kong_coco|kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl mac, not zhaozg lua-openssl mac.ctx; generic final/update text exists but not target mac ctx; no direct target openss|
|10|mbarnes-code/expert-dollop|infrastructure/kong/kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl mac, not zhaozg lua-openssl mac.ctx; generic final/update text exists but not target mac ctx; no direct target openss|
|11|wujiapei/alldata|dataGovern/kong-versions/kong-2.6.0/kong/plugins/hmac-auth/access.lua|false|false|low|uses lua-resty-openssl hmac one-shot; uses lua-openssl hmac, not openssl.mac.ctx; generic final/update text exists but not target mac ctx; n|
|12|LeXinshou/AlokMedia|libs/WebSession.lua|false|false|noise|no direct target openssl.mac.ctx/mac.ctx evidence|
|13|LeXinshou/WebSessionLua|WebSession.lua|false|false|noise|no direct target openssl.mac.ctx/mac.ctx evidence|
|14|Masken8/Studify-Server|main.lua|false|false|low|uses digest, not MAC ctx; no direct target openssl.mac.ctx/mac.ctx evidence|
|15|NickIsADev/erlua|libs/client/Client.lua|false|false|low|uses digest, not MAC ctx; no direct target openssl.mac.ctx/mac.ctx evidence|
|16|Olivine-Labs/lua-jwt|src/jwt/utils.lua|false|false|low|uses lua-openssl hmac, not openssl.mac.ctx; uses digest, not MAC ctx; generic final/update text exists but not target mac ctx; no direct tar|
|17|Optum/kong-upstream-jwt|src/access.lua|false|false|low|uses digest, not MAC ctx; JWT/security context; no direct target openssl.mac.ctx/mac.ctx evidence|
|18|SkylarPlayz348/lua-Spore|src/Spore/Middleware/Auth/OAuth.lua|false|false|low|uses lua-openssl hmac, not openssl.mac.ctx; no direct target openssl.mac.ctx/mac.ctx evidence|
|19|TencentBlueKing/bk-ci|src/gateway/core/lua/resty/jwt.lua|false|false|noise|JWT/security context; generic final/update text exists but not target mac ctx; no direct target openssl.mac.ctx/mac.ctx evidence|
|20|VoidCosmo/waspsaliva|clientmods/wisp/init.lua|false|false|low|uses digest, not MAC ctx; no direct target openssl.mac.ctx/mac.ctx evidence|

## Findings

No high-value real application path was confirmed.

The Top 20 candidates are security-relevant Lua files, but they do not use the target zhaozg/lua-openssl `openssl.mac.ctx` / `mac.ctx` lifecycle API:

- Several Kong/APISIX candidates use `resty.openssl.mac` or `resty.openssl.hmac` for HMAC/JWT one-shot signing or verification.
- Some candidates use lua-openssl `openssl.hmac` or `openssl.digest`, not `openssl.mac.ctx`.
- Direct `mac.ctx` search results were lua-openssl tests or vendored copies of those tests.
- No downloaded candidate showed a real application sequence equivalent to `ctx:final(...) -> ctx:update(...) -> ctx:final(...)` on lua-openssl MAC ctx with attacker-controlled data.

Therefore, this pass did not find a real application-level authentication bypass path.

## Current CVE/CNVD Maturity

Current maturity remains below CVE/CNVD submission threshold.

What is already supported:

- OpenSSL CMAC behavior permits post-final update/final continuation locally.
- mbedTLS PSA MAC rejects post-finish continuation with BAD_STATE.
- lua-openssl exposes `update` / `final` / `close`, and local PoCs show `update -> final -> update -> final` and `final(last_data)` can produce a second CMAC tag.

What is still missing:

- A real application using lua-openssl `openssl.mac.ctx` in security-sensitive logic.
- Evidence that attacker-controlled post-final data reaches `ctx:update` or `ctx:final(last_data)` after a completed MAC final.
- Evidence that this changes an authentication, token, session, signature, permission, or integrity-check decision.
- Upstream confirmation that OpenSSL's CMAC final/resume behavior violates documented contract, rather than legacy/provider semantics.

Classification after this search:

```text
library_semantic_divergence: confirmed locally
lua-openssl binding exposure: confirmed locally
real_application_security_impact: not found
CVE/CNVD readiness: not mature
```

## Next Steps

1. Expand search beyond GitHub code search with targeted package ecosystems: LuaRocks reverse dependencies for `lua-openssl`, OpenResty projects, Kong plugins, and embedded Lua projects.
2. Add search terms for construction patterns, not only API names: `openssl.mac.new`, `openssl.mac.interpose`, `:final(last`, `:final(data`, `CMAC` plus `require("openssl")`.
3. Review lua-resty-openssl separately only if the research scope expands from zhaozg/lua-openssl to all Lua OpenSSL wrappers.
4. Build a minimal upstream-safe advisory draft framed as documentation ambiguity / lifecycle semantic divergence, not confirmed vulnerability.
5. Continue looking for a real app state machine where post-final continuation changes authorization, token verification, session validation, or request-signature verification.
