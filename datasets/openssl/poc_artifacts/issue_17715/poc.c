#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

static int read_x509_path(const char *path)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    int ok = 0;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed for X509: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "PEM_read_bio_X509 failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    printf("PEM_read_bio_X509 succeeded: %s\n", path);
    ok = 1;

end:
    X509_free(cert);
    BIO_free(bio);
    return ok;
}

static int read_req_path(const char *path)
{
    BIO *bio = NULL;
    X509_REQ *req = NULL;
    int ok = 0;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed for request: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (req == NULL) {
        fprintf(stderr, "PEM_read_bio_X509_REQ failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    printf("PEM_read_bio_X509_REQ succeeded: %s\n", path);
    ok = 1;

end:
    X509_REQ_free(req);
    BIO_free(bio);
    return ok;
}

static int parse_pkcs12_path(const char *path)
{
    const char *passphrase = "testpassword";
    FILE *fp = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    int parse_ok;
    int ok = 0;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        perror("fopen");
        goto end;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    if (p12 == NULL) {
        fprintf(stderr, "d2i_PKCS12_fp failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    parse_ok = PKCS12_parse(p12, passphrase, &pkey, &cert, &ca);
    printf("PKCS12_parse returned %d: %s\n", parse_ok, path);
    if (parse_ok != 1) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ok = 1;

end:
    sk_X509_pop_free(ca, X509_free);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    PKCS12_free(p12);
    if (fp != NULL) {
        fclose(fp);
    }
    return ok;
}

static int private_key_roundtrip(const char *path, const char *label)
{
    BIO *in = NULL;
    BIO *out = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    in = BIO_new_file(path, "r");
    if (in == NULL) {
        fprintf(stderr, "BIO_new_file failed for %s key: %s\n", label, path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        fprintf(stderr, "PEM_read_bio_PrivateKey failed for %s key: %s\n", label, path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        fprintf(stderr, "BIO_new_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    printf("PEM_write_bio_PrivateKey for %s key follows:\n", label);
    if (PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "PEM_write_bio_PrivateKey failed for %s key\n", label);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ok = 1;

end:
    EVP_PKEY_free(pkey);
    BIO_free(out);
    BIO_free(in);
    return ok;
}

int main(int argc, char **argv)
{
    int failures = 0;

    if (argc != 6) {
        fprintf(stderr, "Usage: %s <input.pem> <req.pem> <pkcs12.pem> <pkey.pem> <rsa.pem>\n", argv[0]);
        return 2;
    }

    failures += read_x509_path(argv[1]) ? 0 : 1;
    failures += read_req_path(argv[2]) ? 0 : 1;
    failures += parse_pkcs12_path(argv[3]) ? 0 : 1;
    failures += private_key_roundtrip(argv[4], "generic") ? 0 : 1;
    failures += private_key_roundtrip(argv[5], "rsa") ? 0 : 1;

    printf("multi_crypto_cli_path failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
