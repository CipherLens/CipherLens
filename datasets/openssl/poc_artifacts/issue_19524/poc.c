#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(void)
{
    static const unsigned char public_key[32] = {
        0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b,
        0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe, 0xe6, 0x85,
        0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08,
        0xc3, 0xbd, 0xae, 0x36, 0x9e, 0xf5, 0x49, 0xfa,
    };
    static const unsigned char message[] = "Test";
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char sig[128];
    size_t siglen = sizeof(sig);
    int init_ok;
    int sign_ok;
    int ret = 1;

    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                       public_key, sizeof(public_key));
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

    init_ok = EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey);
    printf("EVP_DigestSignInit returned %d\n", init_ok);
    if (init_ok != 1) {
        ERR_print_errors_fp(stderr);
        ret = 0;
        goto end;
    }

    sign_ok = EVP_DigestSign(mdctx, sig, &siglen, message, sizeof(message) - 1);
    printf("EVP_DigestSign returned %d, siglen=%zu\n", sign_ok, siglen);
    if (sign_ok != 1) {
        ERR_print_errors_fp(stderr);
    }

    ret = 0;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ret;
}
