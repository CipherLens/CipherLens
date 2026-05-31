/*
 * Template: EVP_CIPHER_CTX_DUP_UNINIT_STATE
 * Pattern: OPENSSL-ISSUE-8980 (same-library equivalent API variant)
 * Source library: OpenSSL 3.5.5
 * Vulnerability class: evp_context_state_lifecycle
 * Oracle type: crash_sanitizer_oracle
 *
 * Relationship to original PoC:
 *   Original (poc.c): EVP_CIPHER_CTX_copy(dst, src)  -- copy into pre-allocated dst
 *   This variant:     EVP_CIPHER_CTX_dup(src)         -- allocate + copy, return new ctx
 *
 *   EVP_CIPHER_CTX_dup internally calls EVP_CIPHER_CTX_copy, traversing the same
 *   AES-GCM EVP_CTRL_COPY handler path. On OpenSSL 1.0.2 (if EVP_CIPHER_CTX_dup
 *   existed there), it would have triggered the same uninitialized GCM state access.
 *   On OpenSSL 3.5.5, the NULL-guard in EVP_CTRL_COPY produces safe/fixed behavior.
 *
 * Core vulnerability path preserved:
 *   EVP_EncryptInit_ex(src, EVP_aes_128_gcm(), NULL, NULL, NULL)  ← partial init
 *   EVP_CIPHER_CTX_dup(src)  ← dup = alloc + copy of partial GCM context
 *   → buggy path (1.0.2): uninitialized memory access in gcm.key fixup
 *   → safe path (3.5.5): NULL guard skips fixup, returns valid dst or NULL
 *
 * Mutation slots:
 *   [CIPHER_ALGORITHM]  e.g. EVP_aes_128_gcm()
 *   [SRC_KEY_BYTES]     e.g. NULL (not set) — partial init trigger
 *   [SRC_IV_BYTES]      e.g. NULL (not set) — partial init trigger
 */

#include <openssl/evp.h>
#include <stdio.h>

int main(void)
{
    EVP_CIPHER_CTX *src = NULL;
    EVP_CIPHER_CTX *dst = NULL;
    const EVP_CIPHER *cipher = NULL;

    src = EVP_CIPHER_CTX_new();
    if (src == NULL) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto end;
    }

    cipher = [CIPHER_ALGORITHM];
    if (cipher == NULL) {
        fprintf(stderr, "cipher fetch failed\n");
        goto end;
    }

    /*
     * Partial initialization: cipher algorithm associated,
     * but NO key ([SRC_KEY_BYTES]) and NO IV ([SRC_IV_BYTES]).
     * This leaves internal GCM state (gcm.key) uninitialized.
     */
    if (EVP_EncryptInit_ex(src, cipher, NULL, [SRC_KEY_BYTES], [SRC_IV_BYTES]) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        goto end;
    }

    /*
     * Core trigger: EVP_CIPHER_CTX_dup on partially-initialized AES-GCM context.
     * Internally calls EVP_CIPHER_CTX_copy, which invokes EVP_CTRL_COPY on AES-GCM.
     * OpenSSL 3.5.5: NULL guard in EVP_CTRL_COPY handles gcm.key == NULL safely.
     * OpenSSL 1.0.2 equivalent: no NULL guard → uninitialized memory read.
     */
    dst = EVP_CIPHER_CTX_dup(src);

    if (dst == NULL) {
        printf("[OK] EVP_CIPHER_CTX_dup safely rejected duplicate of partial context "
               "(returned NULL).\n");
    } else {
        printf("[INFO] EVP_CIPHER_CTX_dup succeeded on partial context (safe copy on "
               "this OpenSSL version).\n");
    }

end:
    EVP_CIPHER_CTX_free(dst);
    EVP_CIPHER_CTX_free(src);
    return 0;
}
