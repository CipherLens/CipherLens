# ccm_plaintext_length_not_announced_triage_v1 Report

## Summary

- decision: downgrade_to_observation
- reason: minimal harness shows payload-only no-length path can succeed while AAD no-length path rejects; original case was payload-only and the oracle was too strong
- valid_control_passed: True
- candidate_reproduced_in_minimal_harness: True
- oracle_too_strong: True
- ASAN/UBSAN/crash: False / False / False

## Documentation Evidence

本地 manpage 写明 CCM total plaintext/ciphertext length MUST 通过 in/out 为 NULL 的 update 调用传入。同时，本地 provider 源码显示：AAD 路径在未设置 message length 且 AAD length 非零时返回错误；payload update 路径若尚未设置长度，会调用 ccm_set_iv(ctx, len) 使用当前 payload length。因此文档语义与 payload-only 本地实现行为存在张力：带 AAD 缺长度会被拒绝，无 AAD payload-only 缺长度可成功。

```text
本地 OpenSSL manpage 明确描述 CCM total plaintext/ciphertext length 要求。
GCM mode but with a
few additional requirements and different I<ctrl> values.

For CCM mode, the total plaintext or ciphertext length B<MUST> be passed to
EVP_CipherUpdate(), EVP_EncryptUpdate() or EVP_DecryptUpdate() with the output
and input parameters (I<in> and I<out>) set to NULL and the length passed in
the I<inl> parameter.

The following I<ctrl>s are supported in CCM mode.

=over 4

=item EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, taglen, tag)

This call is made to set the expected
本地 OpenSSL provider 源码存在 CCM 长度处理逻辑证据。
(!ctx->iv_set)
        goto err;

    if (out == NULL) {
        if (in == NULL) {
            if (!ccm_set_iv(ctx, len))
                goto err;
        } else {
            /* If we have AAD, we need a message length */
            if (!ctx->len_set && len)
                goto err;
            if (!hw->setaad(ctx, in, len))
                goto err;
        }
    } else {
        /* If not se
ge length */
            if (!ctx->len_set && len)
                goto err;
            if (!hw->setaad(ctx, in, len))
                goto err;
        }
    } else {
        /* If not set length yet do it */
        if (!ctx->len_set && !ccm_set_iv(ctx, len))
            goto err;

        if (ctx->enc) {
            if (!hw->auth_encrypt(ctx, in, out, len, NULL, 0))
                goto err;
cit IV */
    memcpy(ctx->iv + EVP_CCM_TLS_FIXED_IV_LEN, in, EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Correct length value */
    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->m;
    if (!ccm_set_iv(ctx, len))
        goto err;

    /* Use saved AAD */
    if (!ctx->hw->setaad(ctx, ctx->buf, ctx->tls_aad_len))
        goto err;

    /* Fix buffer to point to payload */
    in += EVP_CCM_TLS_EXPLICIT_IV_LE
```

## Policy

No tools script, public target access, exploit chain, main feedback write,
pattern-bank update, git operation, confirmed vulnerability claim, DER
trailing-garbage repeat, full-consumption oracle, UAF, or double-free was used.
