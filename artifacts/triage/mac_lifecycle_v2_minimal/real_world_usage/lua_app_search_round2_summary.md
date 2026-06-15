# Lua Application Search Round 2 Summary

## Scope

This was a final strong-constraint search for real Lua applications using zhaozg/lua-openssl MAC context APIs:

- `openssl.mac.ctx`
- `mac.ctx`
- `mac_ctx:update(...)` / `ctx:update(...)`
- `mac_ctx:final(...)` / `ctx:final(...)`

Associated `openssl.hmac` and `openssl.digest` results were collected only as context. They are not treated as direct evidence for the OpenSSL CMAC `mac_ctx` lifecycle issue.

## Query Status

Successful queries: 11

|name|query|stdout_bytes|
|---|---|---|
|01_mac_ctx_call_openssl_lua|"mac.ctx(" "openssl" language:Lua|932|
|02_openssl_mac_ctx_lua|"openssl.mac.ctx" language:Lua|3|
|05_mac_ctx_token_lua|"mac.ctx" "token" language:Lua|3|
|06_mac_ctx_auth_lua|"mac.ctx" "auth" language:Lua|3|
|07_mac_ctx_signature_lua|"mac.ctx" "signature" language:Lua|3|
|08_mac_ctx_verify_lua|"mac.ctx" "verify" language:Lua|3|
|09_mac_ctx_session_lua|"mac.ctx" "session" language:Lua|3|
|10_mac_ctx_cookie_lua|"mac.ctx" "cookie" language:Lua|3|
|11_openssl_hmac_final_lua|"openssl.hmac" "final" language:Lua|17122|
|12_openssl_digest_final_lua|"openssl.digest" "final" language:Lua|16859|
|13_require_openssl_hmac_final_lua|"require(\"openssl\")" "hmac" "final" language:Lua|2541|

Failed queries: 2

|name|query|error|
|---|---|---|
|03_require_openssl_ctx_update_lua|"require(\"openssl\")" "ctx:update" language:Lua|HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL Unknown language: "Lua\"" (https://api.github.com/search/code?page=1&per_page=50&q=%22require%28%5C%22openssl%5C%22%29%22+%22ctx%3A%22updat|
|04_require_openssl_ctx_final_lua|"require(\"openssl\")" "ctx:final" language:Lua|HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL Unknown language: "Lua\"" (https://api.github.com/search/code?page=1&per_page=50&q=%22require%28%5C%22openssl%5C%22%29%22+%22ctx%3A%22final|

The two failed queries failed due to GitHub code-search parser handling around quoted `ctx:update` / `ctx:final` terms. The failures were recorded and did not stop the workflow.

## Direct Target Query Observations

- `01_mac_ctx_call_openssl_lua.json`: 3 hits
  - `huahua132/skynet_fly` `3rd/lua-openssl/test/2.mac.lua`
  - `zhaozg/lua-openssl` `test/2.mac.lua`
  - `iiAlladin/lua-openssl-quik` `test/2.mac.lua`
- `02_openssl_mac_ctx_lua.json`: 0 hits
- `05_mac_ctx_token_lua.json`: 0 hits
- `06_mac_ctx_auth_lua.json`: 0 hits
- `07_mac_ctx_signature_lua.json`: 0 hits
- `08_mac_ctx_verify_lua.json`: 0 hits
- `09_mac_ctx_session_lua.json`: 0 hits
- `10_mac_ctx_cookie_lua.json`: 0 hits

Interpretation: direct `mac.ctx` / `openssl.mac.ctx` searches did not find real application code. The only non-empty direct target query returned lua-openssl self-test or vendored/forked test copies, which were excluded from ranking.

## Top 10 Ranked Candidates

|rank|score|repo|path|hits|source|
|---|---|---|---|---|---|
|1|36|Kong/lua-resty-aws|src/resty/aws/request/signatures/utils.lua|security:signature,security:request,security:sign|11_openssl_hmac_final_lua.json|
|2|36|xiaomastack/kong-plugin-upstream-auth-signature|kong/plugins/upstream-auth-signature/handler.lua|security:auth,security:signature,security:sign|11_openssl_hmac_final_lua.json|
|3|24|DistributedSystemsProject/AuthorizationServer|server.lua|security:auth,security:server|11_openssl_hmac_final_lua.json|
|4|24|LEGO/kong-aws-request-signing|kong/plugins/aws-request-signing/sigv4.lua|security:request,security:sign|11_openssl_hmac_final_lua.json|
|5|24|ThruInc/haproxy-lua-oauth|lib/jwtverify.lua|security:auth,security:verify|11_openssl_hmac_final_lua.json|
|6|24|carnei-ro/kong-plugin-oauth-jwt-signer|resty-script.lua|security:auth,security:sign|11_openssl_hmac_final_lua.json|
|7|24|haproxytech/haproxy-lua-oauth|lib/jwtverify.lua|security:auth,security:verify|12_openssl_digest_final_lua.json|
|8|15|orlabs/orange|orange/plugins/hmac_auth/handler.lua|security:auth,assoc:hmac|11_openssl_hmac_final_lua.json|
|9|15|starjiang/xorange|orange/plugins/hmac_auth/handler.lua|security:auth,assoc:hmac|11_openssl_hmac_final_lua.json|
|10|12|GustavoMartins123/supabase-multitenant|studio/nginx/lua/auth/check_push_worker.lua|security:auth|12_openssl_digest_final_lua.json|

## Top 30 Assessment Counts

- high: 0
- medium: 0
- low: 29
- noise: 1

## Top 10 Assessment Snapshot

|rank|repo|file|target_mac_ctx|post_final|rating|notes|
|---|---|---|---|---|---|---|
|1|Kong/lua-resty-aws|src/resty/aws/request/signatures/utils.lua|false|false|low|uses lua-resty-openssl hmac; uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists|
|2|xiaomastack/kong-plugin-upstream-auth-signature|kong/plugins/upstream-auth-signature/handler.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists only outside target mac.ctx|
|3|DistributedSystemsProject/AuthorizationServer|server.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; uses lua-openssl digest associated API, not MAC ctx; no target mac.ctx evidence; fin|
|4|LEGO/kong-aws-request-signing|kong/plugins/aws-request-signing/sigv4.lua|false|false|low|uses lua-resty-openssl hmac; uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists|
|5|ThruInc/haproxy-lua-oauth|lib/jwtverify.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; uses lua-openssl digest associated API, not MAC ctx; no target mac.ctx evidence; fin|
|6|carnei-ro/kong-plugin-oauth-jwt-signer|resty-script.lua|false|false|low|uses lua-resty-openssl hmac; uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists|
|7|haproxytech/haproxy-lua-oauth|lib/jwtverify.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; uses lua-openssl digest associated API, not MAC ctx; no target mac.ctx evidence; fin|
|8|orlabs/orange|orange/plugins/hmac_auth/handler.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists only outside target mac.ctx|
|9|starjiang/xorange|orange/plugins/hmac_auth/handler.lua|false|false|low|uses lua-openssl hmac associated API, not CMAC mac.ctx; no target mac.ctx evidence; final/update pattern exists only outside target mac.ctx|
|10|GustavoMartins123/supabase-multitenant|studio/nginx/lua/auth/check_push_worker.lua|false|false|low|uses lua-openssl digest associated API, not MAC ctx; no target mac.ctx evidence|

## Finding

No real application security impact path was found in this final strong-constraint pass.

The downloaded Top 30 candidates are mostly security-relevant Lua files, but they use associated APIs such as:

- `openssl.hmac`
- `openssl.digest`
- `resty.openssl.hmac`
- `resty.openssl.mac`

They do not use zhaozg/lua-openssl `openssl.mac.ctx` / `mac.ctx`, and no candidate shows a post-final sequence such as:

```lua
ctx:final(...)
ctx:update(attacker_controlled_data)
ctx:final(...)
```

or:

```lua
ctx:final(last_data)
```

inside authentication, token, session, signature, permission, or integrity-check logic.

## CVE/CNVD Maturity Judgment

Current maturity remains insufficient for CVE/CNVD submission.

Supported evidence:

- OpenSSL CMAC lifecycle divergence is locally reproducible.
- lua-openssl exposes MAC `update` / `final` / `close` without an obvious finalized-state guard.
- Local lua-openssl PoCs show post-final continuation can produce a second CMAC tag.

Missing evidence:

- No real Lua application was found using zhaozg/lua-openssl `mac.ctx` in security-sensitive logic.
- No attacker-controlled post-final data path was found.
- No authentication/token/session/signature/permission decision was shown to change because of post-final continuation.
- No upstream confirmation that OpenSSL CMAC behavior violates the documented contract rather than legacy/provider semantics.

Final round2 classification:

```text
library_semantic_divergence: confirmed locally
lua-openssl binding exposure: confirmed locally
real_application_security_impact: not found
CVE/CNVD readiness: not mature
```

## Suggested Next Step

Stop CVE/CNVD escalation for now. The strongest defensible next artifact is an upstream clarification report or documentation-ambiguity note about OpenSSL CMAC post-final continuation semantics, plus lua-openssl hardening suggestions such as an optional wrapper-level finalized-state guard.
