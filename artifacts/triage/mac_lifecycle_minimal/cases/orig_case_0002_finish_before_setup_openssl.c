
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static int setup(EVP_MAC **mac, EVP_MAC_CTX **ctx) {
    *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (*mac == NULL) return 0;
    *ctx = EVP_MAC_CTX_new(*mac);
    if (*ctx == NULL) return 0;
    return 1;
}

static int do_init(EVP_MAC_CTX *ctx, const char *digest) {
    static unsigned char key[] = { 's','p','r','i','n','t','-','k','e','y' };
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_MAC_init(ctx, key, sizeof(key), params);
}

static void cleanup(EVP_MAC *mac, EVP_MAC_CTX *ctx) {
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

int main(void) {
    const char *mutation = "finish_before_setup";
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    unsigned char data[] = { 'a', 'b', 'c' };
    unsigned char out[64];
    size_t outl = 0;
    int ret = 0;
    printf("template_mutation API=EVP_MAC MUTATION=%s\n", mutation);
    if (!setup(&mac, &ctx)) {
        printf("[TRIAGE] mac_context_lifecycle: setup failed.\n");
        cleanup(mac, ctx);
        return 0;
    }
    ret = EVP_MAC_final(ctx, out, &outl, sizeof(out));
    printf("final_ret=%d outl=%zu\n", ret, outl);
    if (ret == 1) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state finish_before_setup succeeded.\n");
        cleanup(mac, ctx);
        return 1;
    }
    if (outl != 0) {
        printf("[TRIAGE] mac_context_lifecycle: unexpected size/state finish_before_setup polluted outl on failure.\n");
        cleanup(mac, ctx);
        return 1;
    }
    printf("[OK] mac_context_lifecycle: pre-setup operation rejected safely\n");

    cleanup(mac, ctx);
    return 0;
}
