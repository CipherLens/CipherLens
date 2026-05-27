#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *bio = NULL;
    X509_REQ *req = NULL;
    int print_ok;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <req.pem>\n", argv[0]);
        return 2;
    }

    bio = BIO_new_file(argv[1], "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", argv[1]);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (req == NULL) {
        fprintf(stderr, "PEM_read_bio_X509_REQ failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    print_ok = X509_REQ_print_fp(stdout, req);
    printf("\nX509_REQ_print_fp returned %d\n", print_ok);
    if (print_ok != 1) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    X509_REQ_free(req);
    BIO_free(bio);
    return ret;
}
