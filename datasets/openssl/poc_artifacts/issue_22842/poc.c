#include <stdio.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>

int main(void)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    const unsigned char key[] = "rag-seed-hmac-key";
    size_t mac_size;
    int init_ok;
    int ret = 1;

    mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        fprintf(stderr, "EVP_MAC_fetch(HMAC) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MAC_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    init_ok = EVP_MAC_init(ctx, key, sizeof(key) - 1, params);
    printf("EVP_MAC_init returned %d\n", init_ok);
    if (init_ok != 1) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    mac_size = EVP_MAC_CTX_get_mac_size(ctx);
    printf("EVP_MAC_CTX_get_mac_size returned %zu\n", mac_size);
    if (mac_size == 0) {
        fprintf(stderr, "unexpected zero MAC size\n");
        goto end;
    }

    ret = 0;

end:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return ret;
}
