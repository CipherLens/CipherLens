#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
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

static EVP_PKEY *read_key(const char *path)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        fprintf(stderr, "BIO_new_file failed for key: %s\n", path);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        fprintf(stderr, "PEM_read_bio_PrivateKey failed: %s\n", path);
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    return pkey;
}

int main(int argc, char **argv)
{
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    CMS_ContentInfo *cms = NULL;
    X509_STORE *store = NULL;
    int verify_ok;
    int ret = 1;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s <cert.pem> <key.pem> <text.txt>\n", argv[0]);
        return 2;
    }

    cert = read_cert(argv[1]);
    pkey = read_key(argv[2]);
    if (cert == NULL || pkey == NULL) {
        goto end;
    }

    in = BIO_new_file(argv[3], "rb");
    if (in == NULL) {
        fprintf(stderr, "BIO_new_file failed for content: %s\n", argv[3]);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    cms = CMS_sign(cert, pkey, NULL, in, CMS_BINARY);
    if (cms == NULL) {
        fprintf(stderr, "CMS_sign failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "X509_STORE_new failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
        fprintf(stderr, "X509_STORE_add_cert failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        fprintf(stderr, "BIO_new_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    verify_ok = CMS_verify(cms, NULL, store, NULL, out, CMS_BINARY);
    printf("\nCMS_verify returned %d\n", verify_ok);
    if (verify_ok != 1) {
        ERR_print_errors_fp(stderr);
    }

    ret = 0;

end:
    BIO_free(out);
    X509_STORE_free(store);
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ret;
}
