#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdio.h>
#include <string.h>

struct cmac_result {
    int fetch_ok;
    int ctx_ok;
    int init_ret;
    int update_ret;
    int final_ret;
    unsigned char tag[64];
    size_t tag_len;
};

struct resume_result {
    int fetch_ok;
    int ctx_ok;
    int init_ret;
    int update1_ret;
    int final1_ret;
    int update2_after_final_ret;
    int final_after_resume_ret;
    unsigned char tag1[64];
    unsigned char tag_after_resume[64];
    size_t tag1_len;
    size_t tag_after_resume_len;
};

static const unsigned char message1[] = {
    0x6d, 0x61, 0x63, 0x20, 0x6c, 0x69, 0x66, 0x65,
    0x63, 0x79, 0x63, 0x6c, 0x65, 0x20, 0x6d, 0x73,
    0x67
};

static const unsigned char message2[] = {
    0x72, 0x65, 0x73, 0x75, 0x6d, 0x65, 0x20, 0x63,
    0x6f, 0x6e, 0x74, 0x69, 0x6e, 0x75, 0x61, 0x74,
    0x69, 0x6f, 0x6e
};

static void print_hex_field(const char *name, const unsigned char *buf, size_t len)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int bytes_equal(const unsigned char *a, size_t alen,
                       const unsigned char *b, size_t blen)
{
    return alen == blen && memcmp(a, b, alen) == 0;
}

static struct cmac_result cmac_fresh(const char *cipher_name,
                                     const unsigned char *key,
                                     size_t key_len,
                                     const unsigned char *message,
                                     size_t message_len)
{
    struct cmac_result r;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    memset(&r, 0, sizeof(r));
    r.final_ret = -1;

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    r.fetch_ok = mac != NULL;
    if (mac != NULL) {
        ctx = EVP_MAC_CTX_new(mac);
    }
    r.ctx_ok = ctx != NULL;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *) cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL) {
        r.init_ret = EVP_MAC_init(ctx, key, key_len, params);
        if (r.init_ret == 1) {
            r.update_ret = EVP_MAC_update(ctx, message, message_len);
        }
        if (r.update_ret == 1) {
            r.final_ret = EVP_MAC_final(ctx, r.tag, &r.tag_len, sizeof(r.tag));
        }
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return r;
}

static struct resume_result cmac_resume_path(const char *cipher_name,
                                             const unsigned char *key,
                                             size_t key_len)
{
    struct resume_result r;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    memset(&r, 0, sizeof(r));
    r.final1_ret = -1;
    r.update2_after_final_ret = -1;
    r.final_after_resume_ret = -1;

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    r.fetch_ok = mac != NULL;
    if (mac != NULL) {
        ctx = EVP_MAC_CTX_new(mac);
    }
    r.ctx_ok = ctx != NULL;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *) cipher_name, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (ctx != NULL) {
        r.init_ret = EVP_MAC_init(ctx, key, key_len, params);
        if (r.init_ret == 1) {
            r.update1_ret = EVP_MAC_update(ctx, message1, sizeof(message1));
        }
        if (r.update1_ret == 1) {
            r.final1_ret = EVP_MAC_final(ctx, r.tag1, &r.tag1_len, sizeof(r.tag1));
        }
        if (r.final1_ret == 1) {
            r.update2_after_final_ret = EVP_MAC_update(ctx, message2, sizeof(message2));
        }
        if (r.update2_after_final_ret == 1) {
            r.final_after_resume_ret = EVP_MAC_final(
                ctx,
                r.tag_after_resume,
                &r.tag_after_resume_len,
                sizeof(r.tag_after_resume));
        }
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return r;
}

static void print_cmac_result(const char *prefix, const struct cmac_result *r)
{
    printf("%s_fetch_ok=%d\n", prefix, r->fetch_ok);
    printf("%s_ctx_ok=%d\n", prefix, r->ctx_ok);
    printf("%s_init_ret=%d\n", prefix, r->init_ret);
    printf("%s_update_ret=%d\n", prefix, r->update_ret);
    printf("%s_final_ret=%d\n", prefix, r->final_ret);
    printf("%s_tag_len=%zu\n", prefix, r->tag_len);
    {
        char label[128];
        snprintf(label, sizeof(label), "%s_tag_hex", prefix);
        print_hex_field(label, r->tag, r->tag_len);
    }
}

static void run_algorithm(const char *cipher_name,
                          const unsigned char *key,
                          size_t key_len)
{
    unsigned char concat[sizeof(message1) + sizeof(message2)];
    struct resume_result path_a;
    struct cmac_result path_b;
    struct cmac_result path_c;
    int after_resume_eq_fresh_concat = 0;
    int after_resume_eq_fresh_msg2 = 0;

    memcpy(concat, message1, sizeof(message1));
    memcpy(concat + sizeof(message1), message2, sizeof(message2));

    path_a = cmac_resume_path(cipher_name, key, key_len);
    path_b = cmac_fresh(cipher_name, key, key_len, concat, sizeof(concat));
    path_c = cmac_fresh(cipher_name, key, key_len, message2, sizeof(message2));

    after_resume_eq_fresh_concat = bytes_equal(
        path_a.tag_after_resume,
        path_a.tag_after_resume_len,
        path_b.tag,
        path_b.tag_len);
    after_resume_eq_fresh_msg2 = bytes_equal(
        path_a.tag_after_resume,
        path_a.tag_after_resume_len,
        path_c.tag,
        path_c.tag_len);

    printf("algorithm=%s\n", cipher_name);
    printf("key_len=%zu\n", key_len);
    printf("message1_len=%zu\n", sizeof(message1));
    printf("message2_len=%zu\n", sizeof(message2));

    printf("path_a_fetch_ok=%d\n", path_a.fetch_ok);
    printf("path_a_ctx_ok=%d\n", path_a.ctx_ok);
    printf("path_a_init_ret=%d\n", path_a.init_ret);
    printf("path_a_update1_ret=%d\n", path_a.update1_ret);
    printf("path_a_final1_ret=%d\n", path_a.final1_ret);
    printf("path_a_update2_after_final_ret=%d\n", path_a.update2_after_final_ret);
    printf("path_a_final_after_resume_ret=%d\n", path_a.final_after_resume_ret);
    printf("path_a_tag1_len=%zu\n", path_a.tag1_len);
    print_hex_field("path_a_tag1_hex", path_a.tag1, path_a.tag1_len);
    printf("path_a_tag_after_resume_len=%zu\n", path_a.tag_after_resume_len);
    print_hex_field(
        "path_a_tag_after_resume_hex",
        path_a.tag_after_resume,
        path_a.tag_after_resume_len);

    print_cmac_result("path_b_fresh_concat", &path_b);
    print_cmac_result("path_c_fresh_msg2", &path_c);

    printf("tag_after_resume_eq_fresh_concat=%d\n", after_resume_eq_fresh_concat);
    printf("tag_after_resume_eq_fresh_msg2=%d\n", after_resume_eq_fresh_msg2);
    printf("--\n");
}

int main(void)
{
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

    run_algorithm("AES-128-CBC", key128, sizeof(key128));
    run_algorithm("AES-256-CBC", key256, sizeof(key256));

    ERR_print_errors_fp(stderr);
    return 0;
}
