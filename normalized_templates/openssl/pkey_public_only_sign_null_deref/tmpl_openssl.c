/*
 * Template: PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF
 * Source pattern: OPENSSL-ISSUE-19524
 * Source library: OpenSSL
 * Vulnerability class: pkey_capability_mismatch
 * Oracle type: crash_sanitizer_or_safe_error_oracle
 *
 * Core path:
 *   Create public-only key (no private component)
 *   Attempt EVP_DigestSignInit + EVP_DigestSign
 *   Expected: safe error return (NOT signing success, NOT crash)
 *
 * Mutation slots:
 *   [KEY_TYPE]         e.g. EVP_PKEY_ED25519 / EVP_PKEY_ED448
 *   [KEY_BYTES]        raw public key byte array
 *   [KEY_LEN]          key byte length (32 for ED25519, 57 for ED448)
 *   [MESSAGE_BYTES]    message content
 *   [MESSAGE_LEN]      message length
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void)
{
    static const unsigned char public_key_bytes[[KEY_LEN]] = [KEY_BYTES];
    static const unsigned char message[[MESSAGE_LEN]] = [MESSAGE_BYTES];

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[256];
    size_t siglen = sizeof(sig);
    int init_ok;
    int sign_ok;
    int ret = 1;

    /* Create public-only key — no private component */
    pkey = EVP_PKEY_new_raw_public_key([KEY_TYPE], NULL,
                                       public_key_bytes, sizeof(public_key_bytes));
    if (pkey == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_public_key failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /* Attempt to initialize signing context with public-only key */
    init_ok = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
    printf("EVP_DigestSignInit returned %d\n", init_ok);
    if (init_ok != 1) {
        fprintf(stderr, "[SAFE] EVP_DigestSignInit rejected public-only key\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    /* Attempt to sign with public-only key — core trigger */
    sign_ok = EVP_DigestSign(mdctx, sig, &siglen, message, sizeof(message) - 1);
    printf("EVP_DigestSign returned %d siglen=%zu\n", sign_ok, siglen);
    if (sign_ok != 1) {
        fprintf(stderr, "[SAFE] EVP_DigestSign rejected public-only key\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    /* If we reach here: signing succeeded with public-only key = semantic violation */
    fprintf(stderr, "[WARNING] public-only key signing succeeded — capability mismatch!\n");
    ret = 0;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ret;
}
