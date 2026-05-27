#include <openssl/evp.h>

#define CF_CHECK_EQ(expr, res) if ( (expr) != (res) ) { goto end; }
#define CF_CHECK_NE(expr, res) if ( (expr) == (res) ) { goto end; }

int main(void)
{
    const EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(), *ctx2 = NULL;
    CF_CHECK_NE(cipher = EVP_aes_128_gcm(), NULL);
    CF_CHECK_EQ(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL), 1);
    ctx2 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_copy(ctx2, ctx);
end:
    return 0;
}