#include <openssl/evp.h>
#include <stdio.h>

#define CF_CHECK_EQ(expr, res) if ((expr) != (res)) { goto end; }
#define CF_CHECK_NE(expr, res) if ((expr) == (res)) { goto end; }

int main(void)
{
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER_CTX *ctx2 = NULL;

    ctx = EVP_CIPHER_CTX_new();
    CF_CHECK_NE(ctx, NULL);

    CF_CHECK_NE(cipher = EVP_aes_128_gcm(), NULL);
    CF_CHECK_EQ(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL), 1);

    ctx2 = EVP_CIPHER_CTX_new();
    CF_CHECK_NE(ctx2, NULL);

    EVP_CIPHER_CTX_copy(ctx2, ctx);

end:
    EVP_CIPHER_CTX_free(ctx2);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
