#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static int password_cb(char *buf, int size, int rwflag, void *userdata)
{
    const char *pass = (const char *)userdata;
    int len = (int)strlen(pass);

    (void)rwflag;
    if (len > size) {
        len = size;
    }

    memcpy(buf, pass, (size_t)len);
    return len;
}

int main(int argc, char **argv)
{
    const char *passphrase = "testpassword";
    BIO *in = NULL;
    BIO *out = NULL;
    EVP_PKEY *pkey = NULL;
    int write_ok;
    int ret = 1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <plain.pem>\n", argv[0]);
        return 2;
    }

    in = BIO_new_file(argv[1], "r");
    if (in == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", argv[1]);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    if (pkey == NULL) {
        fprintf(stderr, "PEM_read_bio_PrivateKey failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        fprintf(stderr, "BIO_new_fp failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    write_ok = PEM_write_bio_PrivateKey(out, pkey, EVP_aes_256_cbc(),
                                       NULL, 0, password_cb,
                                       (void *)passphrase);
    printf("\nPEM_write_bio_PrivateKey returned %d\n", write_ok);
    if (write_ok != 1) {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    EVP_PKEY_free(pkey);
    BIO_free(out);
    BIO_free(in);
    return ret;
}
