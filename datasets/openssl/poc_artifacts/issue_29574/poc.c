#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *bio = NULL;
    X509 *cert = NULL;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <cert.disk>\n", argv[0]);
        return 2;
    }

    bio = BIO_new_file(argv[1], "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", argv[1]);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bio = NULL;

    if (cert == NULL) {
        ERR_clear_error();
        bio = BIO_new_file(argv[1], "rb");
        if (bio == NULL) {
            fprintf(stderr, "BIO_new_file failed for DER fallback: %s\n", argv[1]);
            ERR_print_errors_fp(stderr);
            goto end;
        }

        cert = d2i_X509_bio(bio, NULL);
        if (cert == NULL) {
            fprintf(stderr, "certificate parse failed as PEM and DER\n");
            ERR_print_errors_fp(stderr);
            goto end;
        }
    }

    if (X509_print_fp(stdout, cert) != 1) {
        fprintf(stderr, "X509_print_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}
