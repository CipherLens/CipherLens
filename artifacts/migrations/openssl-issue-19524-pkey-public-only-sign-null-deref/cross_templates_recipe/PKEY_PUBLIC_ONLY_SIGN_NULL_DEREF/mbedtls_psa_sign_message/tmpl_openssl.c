/*
 * Template: PKEY_PUBLIC_ONLY_SIGN_NULL_DEREF (OpenSSL source side)
 * Pattern: OPENSSL-ISSUE-19524 (public-only ED25519 key signing capability mismatch)
 * Source API: EVP_PKEY_new_raw_public_key / EVP_DigestSignInit / EVP_DigestSign
 * Library: OpenSSL 3.5.5
 *
 * Mutation slots:
 *   [MESSAGE_LEN]   message length: 4, 0, 16, 64
 *
 * Original bug (OpenSSL 3.0.2 / 1.1.1r):
 *   EVP_DigestSign with public-only key → NULL dereference / SEGV
 * Current behavior (OpenSSL 3.5.5 — fixed):
 *   EVP_DigestSign returns 0 safely ("not a private key")
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void)
{
    static const unsigned char public_key[32] = {
        0x7d,0x4d,0x0e,0x7f,0x61,0x53,0xa6,0x9b,
        0x62,0x42,0xb5,0x22,0xab,0xbe,0xe6,0x85,
        0xfd,0xa4,0x42,0x0f,0x88,0x34,0xb1,0x08,
        0xc3,0xbd,0xae,0x36,0x9e,0xf5,0x49,0xfa
    };
    /* Message of length [MESSAGE_LEN] */
    static const unsigned char message[[MESSAGE_LEN] + 1];

    EVP_PKEY    *pkey   = NULL;
    EVP_MD_CTX  *mdctx  = NULL;
    unsigned char sig[128];
    size_t        siglen = sizeof(sig);
    int init_ret, sign_ret;
    int ret = 1;

    (void)message; /* suppress unused warning when MESSAGE_LEN == 0 */

    /* Create public-only ED25519 key — no private component */
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       public_key, sizeof(public_key));
    if (pkey == NULL) {
        fprintf(stderr, "[ERROR] EVP_PKEY_new_raw_public_key failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) { goto end; }

    /* Attempt signing with public-only key */
    init_ret = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
    printf("EVP_DigestSignInit returned %d\n", init_ret);
    if (init_ret <= 0) {
        ERR_print_errors_fp(stderr);
        printf("[SAFE] EVP_DigestSignInit rejected public-only key\n");
        printf("[VERDICT] safe_reject_behavior\n");
        ret = 0;
        goto end;
    }

    sign_ret = EVP_DigestSign(mdctx, sig, &siglen, message, [MESSAGE_LEN]);
    printf("EVP_DigestSign msg_len=[MESSAGE_LEN] returned %d siglen=%zu\n",
           sign_ret, siglen);
    if (sign_ret <= 0) {
        ERR_print_errors_fp(stderr);
        printf("[SAFE] EVP_DigestSign rejected public-only key signing\n");
        printf("[VERDICT] safe_reject_behavior\n");
        ret = 0;
        goto end;
    }

    fprintf(stderr, "[WARNING] public-only key signing succeeded! Capability mismatch!\n");
    printf("[VERDICT] bug_candidate public-only key signing succeeded\n");
    ret = 1;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ret;
}
