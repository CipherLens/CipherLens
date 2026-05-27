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

static X509_CRL *read_crl(const char *path)
{
    BIO *bio = NULL;
    X509_CRL *crl = NULL;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed for CRL: %s\n", path);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    if (crl == NULL) {
        fprintf(stderr, "PEM_read_bio_X509_CRL failed: %s\n", path);
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    return crl;
}

int main(int argc, char **argv)
{
    X509 *trusted = NULL;
    X509 *cert = NULL;
    X509_CRL *crl = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int verify_ok;
    int err;
    int ret = 1;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cacert.pem> <crl.pem> <cert.pem>\n", argv[0]);
        return 2;
    }

    trusted = read_cert(argv[1]);
    crl = read_crl(argv[2]);
    cert = read_cert(argv[3]);
    if (trusted == NULL || crl == NULL || cert == NULL) {
        goto end;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "X509_STORE_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_add_cert(store, trusted) != 1) {
        fprintf(stderr, "X509_STORE_add_cert failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_add_crl(store, crl) != 1) {
        fprintf(stderr, "X509_STORE_add_crl failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
        fprintf(stderr, "X509_STORE_set_flags failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "X509_STORE_CTX_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
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
    X509_CRL_free(crl);
    X509_free(cert);
    X509_free(trusted);
    return ret;
}
