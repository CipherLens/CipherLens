#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

static void print_out_prefix(const unsigned char *out)
{
    printf("out_prefix=%02x %02x %02x %02x %02x %02x %02x %02x\n",
           out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7]);
}

int main(void)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = NULL;
    unsigned char out[64];
    size_t outl = 0xdeadbeefUL;
    int ret = -1;

    memset(out, 0xaa, sizeof(out));

    if (mac == NULL) {
        printf("[VERDICT] setup_failed\n");
        ERR_print_errors_fp(stderr);
        return 2;
    }
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        printf("[VERDICT] setup_failed\n");
        ERR_print_errors_fp(stderr);
        EVP_MAC_free(mac);
        return 2;
    }

    ret = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    printf("ret=%d\n", ret);
    printf("outl=%zu\n", outl);
    print_out_prefix(out);
    ERR_print_errors_fp(stderr);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    if (ret == 1) {
        printf("[VERDICT] unexpected_success\n");
        return 1;
    }
    if (outl == 0xdeadbeefUL) {
        printf("[VERDICT] safe_failure_outl_unchanged\n");
        return 0;
    }
    printf("[VERDICT] failure_path_outl_modified_triage\n");
    return 1;
}
