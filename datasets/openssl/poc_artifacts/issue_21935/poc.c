#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static BIGNUM *bn_from_dec(const char *dec)
{
    BIGNUM *bn = BN_new();

    if (bn == NULL) {
        return NULL;
    }

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
    int set_key_ok;
    int assign_ok;
    int init_ok;
    int ret = 1;

    pkey = EVP_PKEY_new();
    rsa = RSA_new();
    n = bn_from_dec("3233");
    e = bn_from_dec("17");
    d = bn_from_dec("2753");
    mdctx = EVP_MD_CTX_new();

    if (pkey == NULL || rsa == NULL || n == NULL || e == NULL || d == NULL || mdctx == NULL) {
        fprintf(stderr, "allocation failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    set_key_ok = RSA_set0_key(rsa, n, e, d);
    if (set_key_ok != 1) {
        fprintf(stderr, "RSA_set0_key failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    n = NULL;
    e = NULL;
    d = NULL;

    assign_ok = EVP_PKEY_assign_RSA(pkey, rsa);
    if (assign_ok != 1) {
        fprintf(stderr, "EVP_PKEY_assign_RSA failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }
    rsa = NULL;

    init_ok = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    printf("EVP_DigestSignInit returned %d\n", init_ok);
    if (init_ok != 1) {
        ERR_print_errors_fp(stderr);
    }

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
