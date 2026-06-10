#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/rsa.h>
#include <openssl/store.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRIAGE_ROOT "artifacts/triage/ossl_store_full_consumption"
#define INPUT_ROOT TRIAGE_ROOT "/inputs"

typedef struct {
    const char *name;
    const unsigned char *bytes;
    size_t len;
    int append_second_der;
} suffix_case;

typedef struct {
    const char *kind;
    const char *target_type;
    unsigned char *der;
    int der_len;
} der_input;

static const unsigned char suffix_00[] = {0x00};
static const unsigned char suffix_ff[] = {0xff};
static const unsigned char suffix_null_der[] = {0x05, 0x00};
static const unsigned char suffix_integer_zero[] = {0x02, 0x01, 0x00};
static const unsigned char suffix_empty_sequence[] = {0x30, 0x00};
static const unsigned char suffix_random_8[] = {
    0x83, 0x41, 0xa9, 0x7c, 0x02, 0xee, 0x10, 0x55
};

static const suffix_case SUFFIXES[] = {
    {"baseline_empty", NULL, 0, 0},
    {"trailing_00", suffix_00, sizeof(suffix_00), 0},
    {"trailing_ff", suffix_ff, sizeof(suffix_ff), 0},
    {"trailing_null_der", suffix_null_der, sizeof(suffix_null_der), 0},
    {"trailing_integer_zero", suffix_integer_zero, sizeof(suffix_integer_zero), 0},
    {"trailing_empty_sequence", suffix_empty_sequence, sizeof(suffix_empty_sequence), 0},
    {"trailing_random_8", suffix_random_8, sizeof(suffix_random_8), 0},
    {"second_der_object", NULL, 0, 1},
};

static void print_errors(const char *prefix)
{
    unsigned long err;

    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "[%s] %s\n", prefix, buf);
    }
}

static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (f == NULL)
        return 0;
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return 1;
}

static EVP_PKEY *make_rsa_key(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
        return NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto out;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        goto out;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

out:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509 *make_self_signed_cert(EVP_PKEY *pkey)
{
    X509 *cert = NULL;
    X509_NAME *name = NULL;

    cert = X509_new();
    if (cert == NULL)
        return NULL;
    if (X509_set_version(cert, 2) != 1)
        goto err;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1)
        goto err;
    if (X509_gmtime_adj(X509_get_notBefore(cert), 0) == NULL)
        goto err;
    if (X509_gmtime_adj(X509_get_notAfter(cert), 3600) == NULL)
        goto err;
    if (X509_set_pubkey(cert, pkey) != 1)
        goto err;

    name = X509_get_subject_name(cert);
    if (name == NULL)
        goto err;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"store-triage",
                                   -1, -1, 0) != 1)
        goto err;
    if (X509_set_issuer_name(cert, name) != 1)
        goto err;
    if (X509_sign(cert, pkey, EVP_sha256()) <= 0)
        goto err;

    return cert;

err:
    X509_free(cert);
    return NULL;
}

static int make_der_inputs(der_input inputs[3])
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    int ok = 0;

    memset(inputs, 0, sizeof(der_input) * 3);
    pkey = make_rsa_key();
    if (pkey == NULL)
        goto out;
    cert = make_self_signed_cert(pkey);
    if (cert == NULL)
        goto out;
    p8 = EVP_PKEY2PKCS8(pkey);
    if (p8 == NULL)
        goto out;

    inputs[0].kind = "x509_der";
    inputs[0].target_type = "CERT";
    inputs[0].der_len = i2d_X509(cert, &inputs[0].der);

    inputs[1].kind = "pkcs8_der";
    inputs[1].target_type = "PKEY";
    inputs[1].der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &inputs[1].der);

    inputs[2].kind = "pubkey_der";
    inputs[2].target_type = "PUBKEY";
    inputs[2].der_len = i2d_PUBKEY(pkey, &inputs[2].der);

    ok = inputs[0].der_len > 0 && inputs[1].der_len > 0 && inputs[2].der_len > 0;

out:
    if (!ok) {
        for (size_t i = 0; i < 3; i++) {
            OPENSSL_free(inputs[i].der);
            inputs[i].der = NULL;
            inputs[i].der_len = 0;
        }
        print_errors("SETUP_ERROR");
    }
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return ok;
}

static const char *store_type_name(int type)
{
    switch (type) {
    case OSSL_STORE_INFO_NAME:
        return "NAME";
    case OSSL_STORE_INFO_PARAMS:
        return "PARAMS";
    case OSSL_STORE_INFO_PUBKEY:
        return "PUBKEY";
    case OSSL_STORE_INFO_PKEY:
        return "PKEY";
    case OSSL_STORE_INFO_CERT:
        return "CERT";
    case OSSL_STORE_INFO_CRL:
        return "CRL";
    default:
        return "UNKNOWN";
    }
}

static int is_target_type(const der_input *input, int type)
{
    if (strcmp(input->target_type, "CERT") == 0)
        return type == OSSL_STORE_INFO_CERT;
    if (strcmp(input->target_type, "PKEY") == 0)
        return type == OSSL_STORE_INFO_PKEY;
    if (strcmp(input->target_type, "PUBKEY") == 0)
        return type == OSSL_STORE_INFO_PUBKEY || type == OSSL_STORE_INFO_PKEY;
    return 0;
}

static void touch_store_object(OSSL_STORE_INFO *info, int type)
{
    if (type == OSSL_STORE_INFO_CERT) {
        X509 *cert = OSSL_STORE_INFO_get1_CERT(info);
        X509_free(cert);
    } else if (type == OSSL_STORE_INFO_PKEY) {
        EVP_PKEY *pkey = OSSL_STORE_INFO_get1_PKEY(info);
        EVP_PKEY_free(pkey);
    } else if (type == OSSL_STORE_INFO_PUBKEY) {
        EVP_PKEY *pubkey = OSSL_STORE_INFO_get1_PUBKEY(info);
        EVP_PKEY_free(pubkey);
    }
}

static void run_store_case(const der_input *input, const suffix_case *suffix)
{
    unsigned char *buf = NULL;
    size_t base_len = (size_t)input->der_len;
    size_t second_len = suffix->append_second_der ? base_len : 0;
    size_t total_len = base_len + suffix->len + second_len;
    size_t trailing_len = suffix->len + second_len;
    char path[512];
    OSSL_STORE_CTX *ctx = NULL;
    int store_open_success = 0;
    int store_load_success = 0;
    int target_loaded = 0;
    int info_count = 0;
    int saw_error = 0;
    int saw_eof = 0;
    char type_buf[256] = "";

    snprintf(path, sizeof(path), INPUT_ROOT "/%s_%s.der",
             input->kind, suffix->name);
    buf = OPENSSL_malloc(total_len == 0 ? 1 : total_len);
    if (buf == NULL) {
        printf("[CASE] %s/%s\n", input->kind, suffix->name);
        printf("[INPUT_KIND] %s\n", input->kind);
        printf("[MUTATION] suffix_kind=%s\n", suffix->name);
        printf("[FILE] %s\n", path);
        printf("[RESULT] baseline=%d\n", suffix->len == 0 && !suffix->append_second_der);
        printf("[RESULT] store_open_success=0\n");
        printf("[RESULT] store_load_success=0\n");
        printf("[RESULT] store_info_type=none\n");
        printf("[RESULT] trailing_len=%zu\n", trailing_len);
        printf("[VERDICT] harness_error\n\n");
        return;
    }
    memcpy(buf, input->der, base_len);
    if (suffix->len > 0)
        memcpy(buf + base_len, suffix->bytes, suffix->len);
    if (suffix->append_second_der)
        memcpy(buf + base_len, input->der, base_len);

    if (!write_file(path, buf, total_len)) {
        printf("[CASE] %s/%s\n", input->kind, suffix->name);
        printf("[INPUT_KIND] %s\n", input->kind);
        printf("[MUTATION] suffix_kind=%s\n", suffix->name);
        printf("[FILE] %s\n", path);
        printf("[RESULT] baseline=%d\n", suffix->len == 0 && !suffix->append_second_der);
        printf("[RESULT] store_open_success=0\n");
        printf("[RESULT] store_load_success=0\n");
        printf("[RESULT] store_info_type=none\n");
        printf("[RESULT] trailing_len=%zu\n", trailing_len);
        printf("[VERDICT] harness_error\n\n");
        OPENSSL_free(buf);
        return;
    }

    ERR_clear_error();
    ctx = OSSL_STORE_open(path, NULL, NULL, NULL, NULL);
    store_open_success = ctx != NULL;
    if (ctx != NULL) {
        for (;;) {
            OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);

            if (info != NULL) {
                int type = OSSL_STORE_INFO_get_type(info);
                const char *type_name = store_type_name(type);
                size_t used = strlen(type_buf);

                if (used + strlen(type_name) + 2 < sizeof(type_buf)) {
                    if (used > 0)
                        strcat(type_buf, ",");
                    strcat(type_buf, type_name);
                }
                info_count++;
                if (is_target_type(input, type))
                    target_loaded++;
                touch_store_object(info, type);
                OSSL_STORE_INFO_free(info);
                continue;
            }
            if (OSSL_STORE_eof(ctx)) {
                saw_eof = 1;
                break;
            }
            if (OSSL_STORE_error(ctx)) {
                saw_error = 1;
                break;
            }
            break;
        }
        OSSL_STORE_close(ctx);
    }
    store_load_success = info_count > 0;
    if (type_buf[0] == '\0')
        strcpy(type_buf, "none");

    printf("[CASE] %s/%s\n", input->kind, suffix->name);
    printf("[INPUT_KIND] %s\n", input->kind);
    printf("[MUTATION] suffix_kind=%s\n", suffix->name);
    printf("[FILE] %s\n", path);
    printf("[RESULT] baseline=%d\n", suffix->len == 0 && !suffix->append_second_der);
    printf("[RESULT] store_open_success=%d\n", store_open_success);
    printf("[RESULT] store_load_success=%d\n", store_load_success);
    printf("[RESULT] store_info_type=%s\n", type_buf);
    printf("[RESULT] target_loaded=%d\n", target_loaded);
    printf("[RESULT] info_count=%d\n", info_count);
    printf("[RESULT] saw_eof=%d\n", saw_eof);
    printf("[RESULT] saw_error=%d\n", saw_error);
    printf("[RESULT] trailing_len=%zu\n", trailing_len);
    if (!store_open_success) {
        printf("[VERDICT] harness_error\n\n");
    } else if (suffix->len == 0 && !suffix->append_second_der && target_loaded > 0) {
        printf("[VERDICT] expected_baseline_accept\n\n");
    } else if (suffix->len == 0 && !suffix->append_second_der) {
        printf("[VERDICT] harness_error\n\n");
    } else if (target_loaded > 0) {
        printf("[VERDICT] real_caller_accepts_trailing_garbage_candidate\n\n");
    } else {
        printf("[VERDICT] outer_layer_rejects_trailing_garbage\n\n");
    }

    if (saw_error)
        print_errors("STORE_LOAD_ERROR");
    OPENSSL_free(buf);
}

int main(void)
{
    der_input inputs[3];

    if (!make_der_inputs(inputs)) {
        fprintf(stderr, "failed to generate DER inputs\n");
        return 2;
    }

    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        for (size_t j = 0; j < sizeof(SUFFIXES) / sizeof(SUFFIXES[0]); j++)
            run_store_case(&inputs[i], &SUFFIXES[j]);
    }

    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++)
        OPENSSL_free(inputs[i].der);
    return 0;
}
