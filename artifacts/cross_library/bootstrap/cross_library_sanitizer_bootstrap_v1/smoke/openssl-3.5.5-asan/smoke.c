#include <stdio.h>
#include <openssl/evp.h>
int main(void) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const unsigned char msg[] = "abc";
    int ok = ctx != NULL
        && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1) == 1
        && EVP_DigestFinal_ex(ctx, out, &outlen) == 1;
    EVP_MD_CTX_free(ctx);
    printf("SMOKE_RESULT target=openssl ok=%d outlen=%u\n", ok, outlen);
    return ok ? 0 : 1;
}
