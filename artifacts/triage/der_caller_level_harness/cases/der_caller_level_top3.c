#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *suffix_kind;
    const unsigned char *suffix;
    size_t suffix_len;
    int use_second_object;
} suffix_case;

static const unsigned char suffix_00[] = {0x00};
static const unsigned char suffix_ff[] = {0xff};
static const unsigned char suffix_null_der[] = {0x05, 0x00};
static const unsigned char suffix_empty_seq[] = {0x30, 0x00};

static void print_errors(void)
{
    unsigned long err = 0;
    while ((err = ERR_get_error()) != 0)
        fprintf(stderr, "[ERR] %s\n", ERR_error_string(err, NULL));
}

static int make_key(EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL)
        return 0;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        goto err;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        goto err;
    EVP_PKEY_CTX_free(ctx);
    *out = pkey;
    return 1;

err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int make_cert(EVP_PKEY *pkey, X509 **out)
{
    X509 *x = X509_new();
    X509_NAME *name = NULL;

    if (x == NULL)
        return 0;
    if (!X509_set_version(x, 2))
        goto err;
    if (!ASN1_INTEGER_set(X509_get_serialNumber(x), 1))
        goto err;
    if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL)
        goto err;
    if (X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60 * 24) == NULL)
        goto err;
    if (!X509_set_pubkey(x, pkey))
        goto err;
    name = X509_get_subject_name(x);
    if (name == NULL)
        goto err;
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"der-caller-triage",
                                    -1, -1, 0))
        goto err;
    if (!X509_set_issuer_name(x, name))
        goto err;
    if (!X509_sign(x, pkey, EVP_sha256()))
        goto err;
    *out = x;
    return 1;

err:
    X509_free(x);
    return 0;
}

static int dup_der_from_i2d(int (*i2d_fn)(void *, unsigned char **), void *obj,
                            unsigned char **out, int *out_len)
{
    unsigned char *buf = NULL;
    int len = i2d_fn(obj, &buf);
    if (len <= 0 || buf == NULL)
        return 0;
    *out = buf;
    *out_len = len;
    return 1;
}

static int i2d_pubkey_void(void *obj, unsigned char **out)
{
    return i2d_PUBKEY((EVP_PKEY *)obj, out);
}

static int i2d_pkcs8_void(void *obj, unsigned char **out)
{
    return i2d_PKCS8_PRIV_KEY_INFO((PKCS8_PRIV_KEY_INFO *)obj, out);
}

static int i2d_x509_void(void *obj, unsigned char **out)
{
    return i2d_X509((X509 *)obj, out);
}

static unsigned char *make_mutated(const unsigned char *base, size_t base_len,
                                   const suffix_case *sc,
                                   const unsigned char *second, size_t second_len,
                                   size_t *out_len)
{
    size_t extra_len = sc->use_second_object ? second_len : sc->suffix_len;
    unsigned char *buf = OPENSSL_malloc(base_len + extra_len);

    if (buf == NULL)
        return NULL;
    memcpy(buf, base, base_len);
    if (extra_len > 0) {
        if (sc->use_second_object)
            memcpy(buf + base_len, second, second_len);
        else
            memcpy(buf + base_len, sc->suffix, sc->suffix_len);
    }
    *out_len = base_len + extra_len;
    return buf;
}

static void report_result(const char *case_name, const char *caller,
                          const char *api, const char *suffix_kind,
                          int parse_success, size_t der_len,
                          size_t consumed_len, int caller_accept)
{
    size_t trailing_len = consumed_len <= der_len ? der_len - consumed_len : 0;

    printf("[CASE] %s\n", case_name);
    printf("[CALLER] %s\n", caller);
    printf("[API] %s\n", api);
    printf("[MUTATION] suffix_kind=%s\n", suffix_kind);
    printf("[RESULT] parse_success=%d\n", parse_success);
    printf("[RESULT] der_len=%zu\n", der_len);
    printf("[RESULT] consumed_len=%zu\n", consumed_len);
    printf("[RESULT] trailing_len=%zu\n", trailing_len);
    printf("[RESULT] caller_accept=%d\n", caller_accept);
    if (parse_success && consumed_len < der_len && caller_accept)
        printf("[VERDICT] caller_accepts_trailing_garbage\n");
    else if (parse_success && consumed_len == der_len && caller_accept)
        printf("[VERDICT] baseline_accept_full_consumption\n");
    else if (parse_success && consumed_len < der_len && !caller_accept)
        printf("[VERDICT] caller_rejects_trailing_garbage\n");
    else
        printf("[VERDICT] harness_error\n");
    printf("\n");
}

static void run_pubkey_case(const unsigned char *base, size_t base_len,
                            const suffix_case *sc,
                            const unsigned char *second, size_t second_len)
{
    size_t der_len = 0;
    unsigned char *der = make_mutated(base, base_len, sc, second, second_len, &der_len);
    const unsigned char *p = der;
    EVP_PKEY *pkey = NULL;
    size_t consumed = 0;
    int parse_success = 0;
    int caller_accept = 0;

    if (der == NULL) {
        report_result("ct_b64_pubkey_mode", "ct_b64.c:154 equivalent",
                      "d2i_PUBKEY_ex", sc->suffix_kind, 0, 0, 0, 0);
        return;
    }
    pkey = d2i_PUBKEY_ex(NULL, &p, (long)der_len, NULL, NULL);
    consumed = (size_t)(p - der);
    parse_success = pkey != NULL;
    caller_accept = pkey != NULL;
    report_result("ct_b64_pubkey_mode", "ct_b64.c:154 equivalent",
                  "d2i_PUBKEY_ex", sc->suffix_kind, parse_success, der_len,
                  consumed, caller_accept);
    EVP_PKEY_free(pkey);
    OPENSSL_free(der);
}

static void run_pkcs8_case(const unsigned char *base, size_t base_len,
                           const suffix_case *sc,
                           const unsigned char *second, size_t second_len)
{
    size_t der_len = 0;
    unsigned char *der = make_mutated(base, base_len, sc, second, second_len, &der_len);
    const unsigned char *derp = der;
    PKCS8_PRIV_KEY_INFO *p8info = NULL;
    EVP_PKEY *pk = NULL;
    size_t consumed = 0;
    int parse_success = 0;
    int caller_accept = 0;

    if (der == NULL) {
        report_result("store_result_pkcs8_mode", "store_result.c:384 equivalent",
                      "d2i_PKCS8_PRIV_KEY_INFO", sc->suffix_kind, 0, 0, 0, 0);
        return;
    }
    p8info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &derp, (long)der_len);
    consumed = (size_t)(derp - der);
    parse_success = p8info != NULL;
    if (p8info != NULL)
        pk = EVP_PKCS82PKEY_ex(p8info, NULL, NULL);
    caller_accept = pk != NULL;
    report_result("store_result_pkcs8_mode", "store_result.c:384 equivalent",
                  "d2i_PKCS8_PRIV_KEY_INFO", sc->suffix_kind, parse_success,
                  der_len, consumed, caller_accept);
    EVP_PKEY_free(pk);
    PKCS8_PRIV_KEY_INFO_free(p8info);
    OPENSSL_free(der);
}

static void run_x509_case(const unsigned char *base, size_t base_len,
                          const suffix_case *sc,
                          const unsigned char *second, size_t second_len)
{
    size_t der_len = 0;
    unsigned char *der = make_mutated(base, base_len, sc, second, second_len, &der_len);
    const unsigned char *p = der;
    X509 *cert = NULL;
    size_t consumed = 0;
    int parse_success = 0;
    int caller_accept = 0;

    if (der == NULL) {
        report_result("store_result_x509_mode", "store_result.c:501 equivalent",
                      "d2i_X509", sc->suffix_kind, 0, 0, 0, 0);
        return;
    }
    cert = d2i_X509(NULL, &p, (long)der_len);
    consumed = (size_t)(p - der);
    parse_success = cert != NULL;
    caller_accept = cert != NULL;
    report_result("store_result_x509_mode", "store_result.c:501 equivalent",
                  "d2i_X509", sc->suffix_kind, parse_success, der_len,
                  consumed, caller_accept);
    X509_free(cert);
    OPENSSL_free(der);
}

int main(void)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *pub_der = NULL, *p8_der = NULL, *cert_der = NULL;
    int pub_len = 0, p8_len = 0, cert_len = 0;
    suffix_case cases[] = {
        {"baseline_empty", NULL, 0, 0},
        {"trailing_00", suffix_00, sizeof(suffix_00), 0},
        {"trailing_ff", suffix_ff, sizeof(suffix_ff), 0},
        {"trailing_null_der", suffix_null_der, sizeof(suffix_null_der), 0},
        {"trailing_empty_sequence", suffix_empty_seq, sizeof(suffix_empty_seq), 0},
        {"valid_prefix_plus_second_der_object", NULL, 0, 1},
    };
    size_t i;

    ERR_load_crypto_strings();
    if (!make_key(&pkey) || !make_cert(pkey, &cert))
        goto err;
    p8 = EVP_PKEY2PKCS8(pkey);
    if (p8 == NULL)
        goto err;
    if (!dup_der_from_i2d(i2d_pubkey_void, pkey, &pub_der, &pub_len))
        goto err;
    if (!dup_der_from_i2d(i2d_pkcs8_void, p8, &p8_der, &p8_len))
        goto err;
    if (!dup_der_from_i2d(i2d_x509_void, cert, &cert_der, &cert_len))
        goto err;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        run_pkcs8_case(p8_der, (size_t)p8_len, &cases[i], p8_der, (size_t)p8_len);
        run_x509_case(cert_der, (size_t)cert_len, &cases[i], cert_der, (size_t)cert_len);
        run_pubkey_case(pub_der, (size_t)pub_len, &cases[i], pub_der, (size_t)pub_len);
    }

    OPENSSL_free(pub_der);
    OPENSSL_free(p8_der);
    OPENSSL_free(cert_der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 0;

err:
    fprintf(stderr, "[VERDICT] harness_error\n");
    print_errors();
    OPENSSL_free(pub_der);
    OPENSSL_free(p8_der);
    OPENSSL_free(cert_der);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 2;
}
