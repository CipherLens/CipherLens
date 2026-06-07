/*
 * Template: RSA_TINY_KEY_DIGEST_SIGN_NULL_DEREF
 * Source pattern: OPENSSL-ISSUE-21935
 * Source library: OpenSSL
 * Vulnerability class: rsa_invalid_key_sign_rejection
 * Oracle type: rsa_invalid_key_sign_rejection_oracle
 *
 * Core path:
 *   Construct tiny/invalid RSA key material.
 *   Assign it into EVP_PKEY.
 *   Attempt EVP_DigestSignInit + EVP_DigestSign.
 *   Expected: safe rejection, not crash and not successful signing.
 *
 * Mutation slots:
 *   15       decimal RSA modulus
 *   3       decimal RSA public exponent
 *   2753       decimal RSA private exponent
 *   EVP_sha256()          EVP digest selector
 *   {
    0x54, 0x65, 0x73, 0x74, 0x00
}   message content
 *   5     declared message array length
 *   256     signature buffer length
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static void bug_signal_handler(int signo)
{
    fprintf(stderr, "[BUG] crash or sanitizer signal: %d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

static BIGNUM *bn_from_dec_or_null(const char *dec)
{
    BIGNUM *bn = NULL;

    if (BN_dec2bn(&bn, dec) == 0) {
        BN_free(bn);
        return NULL;
    }

    return bn;
}

int main(void)
{
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    EVP_MD_CTX *mdctx = NULL;
    static const unsigned char message[5] = {
    0x54, 0x65, 0x73, 0x74, 0x00
};
    unsigned char sig[256];
    size_t sig_len = sizeof(sig);
    int set_key_ok = 0;
    int assign_ok = 0;
    int init_ok = 0;
    int sign_ok = 0;
    int ret = 1;

    setbuf(stdout, NULL);
    signal(SIGSEGV, bug_signal_handler);
    signal(SIGABRT, bug_signal_handler);
    signal(SIGBUS, bug_signal_handler);
    signal(SIGILL, bug_signal_handler);
    memset(sig, 0, sizeof(sig));

    pkey = EVP_PKEY_new();
    rsa = RSA_new();
    n = bn_from_dec_or_null("15");
    e = bn_from_dec_or_null("3");
    d = bn_from_dec_or_null("2753");
    mdctx = EVP_MD_CTX_new();

    if (pkey == NULL || rsa == NULL || n == NULL || e == NULL ||
        d == NULL || mdctx == NULL) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected during allocation/setup\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    set_key_ok = RSA_set0_key(rsa, n, e, d);
    printf("RSA_set0_key returned %d\n", set_key_ok);
    if (set_key_ok != 1) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected by RSA_set0_key\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }
    n = NULL;
    e = NULL;
    d = NULL;

    assign_ok = EVP_PKEY_assign_RSA(pkey, rsa);
    printf("EVP_PKEY_assign_RSA returned %d\n", assign_ok);
    if (assign_ok != 1) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected by EVP_PKEY_assign_RSA\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }
    rsa = NULL;

    init_ok = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    printf("EVP_DigestSignInit returned %d\n", init_ok);
    if (init_ok != 1) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected by EVP_DigestSignInit\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    sign_ok = EVP_DigestSign(mdctx, sig, &sig_len, message, sizeof(message) - 1);
    printf("EVP_DigestSign returned %d sig_len=%zu\n", sign_ok, sig_len);
    if (sign_ok != 1) {
        fprintf(stderr, "[SAFE] invalid RSA key signing rejected by EVP_DigestSign\n");
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    fprintf(stderr, "[TRIAGE] signing with invalid RSA key succeeded\n");
    ret = 0;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    return ret;
}
