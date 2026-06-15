# lua-openssl CMAC post-final update runtime assessment

## Candidate

- Project: zhaozg/lua-openssl
- File: src/mac.c
- Binding: Lua binding for OpenSSL EVP_MAC
- Linked OpenSSL: 3.5.5 static libcrypto
- Algorithm: CMAC-AES-128-CBC

## Static observation

The `openssl.mac_ctx` object exposes public Lua methods:

- `update`
- `final`
- `close`

The `update()` method directly calls `EVP_MAC_update()`.

The `final()` method directly calls `EVP_MAC_final()` on the same `EVP_MAC_CTX`.
If a string argument is provided to `final()`, it first calls `EVP_MAC_update()`
with that string and then calls `EVP_MAC_final()`.

No explicit finalized/done/closed state guard was observed around these methods
in the reviewed binding code.

## Runtime PoC result

The following Lua-level sequence was executed:

    ctx:update("authorized-prefix")
    ctx:final(true)
    ctx:update("post-final-data")
    ctx:final(true)

Observed output:

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
    application_decision=APPLICATION_ACCEPTED_POST_FINAL_UPDATE

## Assessment

The runtime PoC confirms that lua-openssl exposes OpenSSL CMAC post-final
continuation behavior to Lua callers through its public `mac_ctx:update()` and
`mac_ctx:final()` methods.

This is stronger than a local toy example because the behavior is reachable
through a real open-source language binding.

However, this is not yet a confirmed authentication bypass or CVE-level
vulnerability. To reach that level, further evidence would be needed showing
that a real Lua application uses this API in a security decision and assumes
that `final()` closes the MAC operation.

Current classification:

    real-world binding-level lifecycle misuse exposure candidate


## Additional PoC: final(last_data) after final()

A second Lua-level PoC tested the following sequence:

    ctx:update("authorized-prefix")
    ctx:final(true)
    ctx:final("post-final-data", true)

Observed output:

    library=lua-openssl
    linked_openssl=3.5.5-static
    algorithm=CMAC-AES-128-CBC
    update1=true
    tag1_len=16
    tag1=dafa7c3408028a29eaa19a33d4c4d936
    final_with_post_final_data_tag2_len=16
    tag2=94d0db38424271a2bedb1f8f24ed98b9
    tag1_eq_tag2=false
    application_decision=APPLICATION_ACCEPTED_FINAL_WITH_POST_FINAL_DATA

## Strengthened assessment

This confirms two reachable Lua-level post-final continuation paths:

1. `update -> final -> update -> final`
2. `update -> final -> final(last_data)`

The second path is especially relevant because `final(last_data)` is an API shape
provided by the binding itself: after a previous `final()`, the same method can
still accept additional data and return another CMAC tag.

This strengthens the classification from a local OpenSSL lifecycle observation to
a real-world language-binding lifecycle exposure.

Current classification remains:

    real-world binding-level lifecycle misuse exposure candidate

It is still not a confirmed authentication bypass without a real application that
uses this behavior in a security decision.
