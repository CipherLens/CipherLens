#include <stdio.h>
#include <time.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;
    const ASN1_TIME *not_after = NULL;
    time_t check_time;
    int cmp;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cert.pem>\n", argv[0]);
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

    not_after = X509_get0_notAfter(cert);
    if (not_after == NULL) {
        fprintf(stderr, "X509_get0_notAfter returned NULL\n");
        goto end;
    }

    check_time = time(NULL);
    cmp = X509_cmp_time(not_after, &check_time);

    if (cmp < 0) {
        printf("Certificate has expired or is invalid at current time.\n");
    } else if (cmp > 0) {
        printf("Certificate is valid beyond current time.\n");
    } else {
        printf("X509_cmp_time returned 0, parse error or comparison failure.\n");
    }

    ret = 0;

end:
    X509_free(cert);
    BIO_free(bio);
    return ret;
}
