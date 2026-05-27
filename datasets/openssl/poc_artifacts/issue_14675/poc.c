#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int verify_ret;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cert_bundle.pem>\n", argv[0]);
        return 2;
    }

    path = argv[1];

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "PEM_read_bio_X509 failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "X509_STORE_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    /*
     * This mirrors a simplified self-verification path:
     * the same cert is used as both target cert and trust anchor.
     * The original CLI issue concerns how openssl verify handles
     * extra invalid content in a certificate file.
     */
    if (X509_STORE_add_cert(store, cert) != 1) {
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

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "X509_STORE_CTX_init failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    verify_ret = X509_verify_cert(ctx);
    printf("X509_verify_cert returned: %d\n", verify_ret);

    if (verify_ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        printf("verify error: %d:%s\n", err, X509_verify_cert_error_string(err));
    }

    ret = 0;

end:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    BIO_free(bio);
    return ret;
}
