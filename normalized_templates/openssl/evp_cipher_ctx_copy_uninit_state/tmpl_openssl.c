/*
 * Template: EVP_CIPHER_CTX_COPY_UNINIT_STATE
 * Source pattern: OPENSSL-ISSUE-8980
 * Source library: OpenSSL
 * Vulnerability class: evp_context_state_lifecycle
 * Oracle type: crash_sanitizer_oracle
 *
 * Core path:
 *   allocate source context
 *   associate cipher algorithm (no key, no IV)
 *   allocate destination context
 *   copy partially-initialized context → potential crash / uninit memory read
 *
 * Mutation slots (replace bracketed tokens for case generation):
 *   [CIPHER_ALGORITHM]    e.g. EVP_aes_128_gcm()
 *   [SRC_KEY_BYTES]       e.g. NULL (not set) or a valid key pointer
 *   [SRC_IV_BYTES]        e.g. NULL (not set) or a valid IV pointer
 */

#include <openssl/evp.h>
#include <stdio.h>

#define CF_CHECK_EQ(expr, res) if ((expr) != (res)) { goto end; }
#define CF_CHECK_NE(expr, res) if ((expr) == (res)) { goto end; }

int main(void)
{
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *ctx2 = NULL;
    int copy_ret;

    ctx = EVP_CIPHER_CTX_new();
    CF_CHECK_NE(ctx, NULL);

    CF_CHECK_NE(cipher = [CIPHER_ALGORITHM], NULL);

    /* Initialize context with cipher but WITHOUT key or IV (partial init) */
    CF_CHECK_EQ(EVP_EncryptInit_ex(ctx, cipher, NULL, [SRC_KEY_BYTES], [SRC_IV_BYTES]), 1);

    ctx2 = EVP_CIPHER_CTX_new();
    CF_CHECK_NE(ctx2, NULL);

    /* Core trigger: copy a partially-initialized GCM context */
    copy_ret = EVP_CIPHER_CTX_copy(ctx2, ctx);
    printf("EVP_CIPHER_CTX_copy returned %d\n", copy_ret);

end:
    EVP_CIPHER_CTX_free(ctx2);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
