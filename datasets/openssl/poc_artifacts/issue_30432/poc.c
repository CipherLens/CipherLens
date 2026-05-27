#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static X509 *read_cert(const char *path)
{
    BIO *bio = NULL;
    X509 *cert = NULL;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed for certificate: %s\n", path);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "PEM_read_bio_X509 failed: %s\n", path);
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    return cert;
}

int main(int argc, char **argv)
{
    X509 *ca = NULL;
    X509 *ee = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int verify_ok;
    int err;
    int ret = 1;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ca_cert.pem> <ee_cert.pem>\n", argv[0]);
        return 2;
    }

    ca = read_cert(argv[1]);
    ee = read_cert(argv[2]);
    if (ca == NULL || ee == NULL) {
        goto end;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "X509_STORE_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_add_cert(store, ca) != 1) {
        fprintf(stderr, "X509_STORE_add_cert failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "X509_STORE_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_CTX_init(ctx, store, ee, NULL) != 1) {
        fprintf(stderr, "X509_STORE_CTX_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    verify_ok = X509_verify_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    printf("X509_verify_cert returned %d\n", verify_ok);
    printf("verification error code: %d\n", err);
    printf("verification error string: %s\n", X509_verify_cert_error_string(err));

    ret = 0;

end:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(ee);
    X509_free(ca);
    return ret;
}
