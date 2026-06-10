#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

static const unsigned char key128[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const unsigned char key256[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const unsigned char msg[17] = {
    0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
    0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
    0x67
};

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", label);
    for (i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static void run_case(const char *case_name,
                     const char *cipher_name,
                     const unsigned char *key,
                     size_t key_len,
                     int do_update)
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];
    unsigned char out1[64];
    unsigned char out2[64];
    unsigned char out3[64];
    size_t outl1 = 111;
    size_t outl2 = 222;
    size_t outl3 = 333;
    int init_ret = 0;
    int update_ret = 1;
    int first_final_ret = 0;
    int second_final_ret = 0;
    int can_update_after_second_final = 0;
    int third_final_ret = 0;
    int out_buffers_equal = 0;

    memset(out1, 0xa5, sizeof(out1));
    memset(out2, 0x5a, sizeof(out2));
    memset(out3, 0x3c, sizeof(out3));

    printf("case=%s cipher=%s key_len=%zu do_update=%d\n",
           case_name, cipher_name, key_len, do_update);

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac == NULL) {
        printf("fetch_failed=1\n\n");
        return;
    }
    ctx = EVP_MAC_CTX_new(mac);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *)cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    init_ret = EVP_MAC_init(ctx, key, key_len, params);
    if (init_ret == 1 && do_update)
        update_ret = EVP_MAC_update(ctx, msg, sizeof(msg));
    first_final_ret = init_ret == 1 && update_ret == 1
                          ? EVP_MAC_final(ctx, out1, &outl1, sizeof(out1))
                          : 0;
    second_final_ret = first_final_ret == 1
                           ? EVP_MAC_final(ctx, out2, &outl2, sizeof(out2))
                           : 0;
    out_buffers_equal = outl1 == outl2 && memcmp(out1, out2, outl1) == 0;
    can_update_after_second_final = EVP_MAC_update(ctx, msg, sizeof(msg));
    third_final_ret = EVP_MAC_final(ctx, out3, &outl3, sizeof(out3));

    printf("init_ret=%d\n", init_ret);
    printf("update_ret=%d\n", update_ret);
    printf("first_final_ret=%d\n", first_final_ret);
    printf("second_final_ret=%d\n", second_final_ret);
    printf("outl1=%zu\n", outl1);
    printf("outl2=%zu\n", outl2);
    print_hex("out1_hex", out1, outl1 <= sizeof(out1) ? outl1 : 0);
    print_hex("out2_hex", out2, outl2 <= sizeof(out2) ? outl2 : 0);
    printf("out_buffers_equal=%d\n", out_buffers_equal);
    printf("can_update_after_second_final=%d\n", can_update_after_second_final);
    printf("third_final_ret=%d\n", third_final_ret);
    printf("outl3=%zu\n\n", outl3);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
}

int main(void)
{
    run_case("aes128_setup_final_final", "AES-128-CBC", key128, sizeof(key128), 0);
    run_case("aes128_setup_update_final_final", "AES-128-CBC", key128, sizeof(key128), 1);
    run_case("aes256_setup_final_final", "AES-256-CBC", key256, sizeof(key256), 0);
    run_case("aes256_setup_update_final_final", "AES-256-CBC", key256, sizeof(key256), 1);
    return 0;
}
