Hi,

I am reviewing MAC lifecycle behavior in lua-openssl and noticed a potentially surprising behavior for CMAC contexts.

The `openssl.mac_ctx` object exposes public `update()` and `final()` methods. From `src/mac.c`, `update()` calls `EVP_MAC_update()` directly, and `final()` calls `EVP_MAC_final()` directly on the same `EVP_MAC_CTX`. In addition, `final(last_data)` first calls `EVP_MAC_update()` with `last_data` and then calls `EVP_MAC_final()`.

I tested this with CMAC-AES-128-CBC and OpenSSL 3.5.5. The following Lua-level sequence succeeded:

```lua
ctx:update("authorized-prefix")
ctx:final(true)
ctx:update("post-final-data")
ctx:final(true)
```

The following sequence also succeeded:

```lua
ctx:update("authorized-prefix")
ctx:final(true)
ctx:final("post-final-data", true)
```

In both cases, the post-final operation produced a second 16-byte CMAC tag.

Example result for `update -> final -> update -> final`:

```text
library=lua-openssl
linked_openssl=3.5.5-static
algorithm=CMAC-AES-128-CBC
update1=true
tag1_len=16
tag1=dafa7c3408028a29eaa19a33d4c4d936
post_final_update=true
tag2_len=16
tag2=94d0db38424271a2bedb1f8f24ed98b9
tag1_eq_tag2=false
```

Example result for `final(last_data)` after a previous `final()`:

```text
library=lua-openssl
linked_openssl=3.5.5-static
algorithm=CMAC-AES-128-CBC
update1=true
tag1_len=16
tag1=dafa7c3408028a29eaa19a33d4c4d936
final_with_post_final_data_tag2_len=16
tag2=94d0db38424271a2bedb1f8f24ed98b9
tag1_eq_tag2=false
```

I am not claiming this is a confirmed vulnerability. I also did not find a real application-level authentication bypass path. My question is about the intended lifecycle semantics of `mac_ctx:final()`:

- Should `final()` make the MAC context finalized or closed?
- Should `update()` be rejected after `final()`?
- Should `final(last_data)` be rejected if the context has already been finalized?
- Or is this behavior intentionally inherited from OpenSSL and expected to be handled by callers?

If this behavior is intended, it may be useful to document it explicitly. If not intended, one possible hardening approach would be to track a binding-level `finalized` state and reject `update()` or repeated `final(last_data)` after successful finalization.

Thanks.
