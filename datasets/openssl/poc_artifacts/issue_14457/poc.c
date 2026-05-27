#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *bio = NULL;
    X509 *root = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;
    int verify_ok;
    int err;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <root.cer>\n", argv[0]);
        return 2;
    }

    bio = BIO_new_file(argv[1], "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", argv[1]);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    root = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (root == NULL) {
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

    if (X509_STORE_add_cert(store, root) != 1) {
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

    if (X509_STORE_CTX_init(ctx, store, root, NULL) != 1) {
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
    X509_free(root);
    BIO_free(bio);
    return ret;
}
