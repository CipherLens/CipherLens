# lua-openssl MAC lifecycle review

## Candidate

- Repository: zhaozg/lua-openssl
- File: src/mac.c
- Candidate type: Lua binding for OpenSSL EVP_MAC

## Observed binding behavior

The reviewed file registers `openssl.mac_ctx` methods including:

- `update`
- `final`
- `close`
- `size`
- `dup`
- `mac`
- `params`

The `update` method calls `EVP_MAC_update()` directly on the underlying
`EVP_MAC_CTX`.

The `final` method calls `EVP_MAC_final()` directly on the same underlying
`EVP_MAC_CTX`. It also accepts an optional string argument and calls
`EVP_MAC_update()` with that string before finalization.

No explicit finalized/done/closed state guard was observed around the
`update()` or `final()` methods in the reviewed code fragment.

## Relevance to this triage

The project-local OpenSSL CMAC lifecycle experiments showed that OpenSSL CMAC
allows post-final update and can produce a new tag after a second finalization.

Because lua-openssl exposes `update()` and `final()` as public Lua methods on
the same MAC context object, the OpenSSL CMAC post-final continuation behavior
may be reachable from Lua code.

A potentially reachable misuse pattern is:

    ctx:update("prefix")
    ctx:final()
    ctx:update("post-final-data")
    ctx:final()

## Current status

This is not yet a confirmed vulnerability.

The next step is to build or run lua-openssl and confirm whether a Lua script can
actually trigger post-final update on a CMAC context and obtain a second tag.

If confirmed, this should be classified as a real-world binding-level lifecycle
misuse exposure / migration-risk candidate, not as a direct OpenSSL
cryptographic break.
