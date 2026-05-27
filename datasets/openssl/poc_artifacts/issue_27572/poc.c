#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    const char *path = NULL;
    BIO *in = NULL;
    BIO *out = NULL;
    unsigned char *buf = NULL;
    unsigned char tmp[4096];
    size_t cap = 0;
    size_t len = 0;
    int n;
    int ret = 1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.der>\n", argv[0]);
        return 2;
    }

    path = argv[1];

    in = BIO_new_file(path, "rb");
    if (in == NULL) {
        fprintf(stderr, "BIO_new_file failed: %s\n", path);
        ERR_print_errors_fp(stderr);
        goto end;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        fprintf(stderr, "BIO_new_fp(stdout) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    while ((n = BIO_read(in, tmp, sizeof(tmp))) > 0) {
        if (len + (size_t)n > cap) {
            size_t new_cap = cap == 0 ? 8192 : cap * 2;
            while (new_cap < len + (size_t)n) {
                new_cap *= 2;
            }

            unsigned char *new_buf = realloc(buf, new_cap);
            if (new_buf == NULL) {
                fprintf(stderr, "realloc failed\n");
                goto end;
            }

            buf = new_buf;
            cap = new_cap;
        }

        memcpy(buf + len, tmp, (size_t)n);
        len += (size_t)n;
    }

    if (len == 0) {
        fprintf(stderr, "empty input\n");
        goto end;
    }

    if (!ASN1_parse_dump(out, buf, (long)len, 0, 0)) {
        fprintf(stderr, "ASN1_parse_dump failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    ret = 0;

end:
    free(buf);
    BIO_free(out);
    BIO_free(in);
    return ret;
}
