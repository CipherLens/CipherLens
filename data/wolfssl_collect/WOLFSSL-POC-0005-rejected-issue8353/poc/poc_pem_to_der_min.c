#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static unsigned char* read_file(const char* path, long* out_len)
{
    FILE* f;
    long n;
    unsigned char* buf;

    f = fopen(path, "rb");
    if (f == NULL) {
        perror("fopen");
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }

    n = ftell(f);
    if (n < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }

    rewind(f);

    buf = (unsigned char*)malloc((size_t)n + 1);
    if (buf == NULL) {
        perror("malloc");
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        perror("fread");
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    buf[n] = 0;
    *out_len = n;
    return buf;
}

int main(int argc, char** argv)
{
    unsigned char* pem;
    long pem_len;
    int ret;
    DerBuffer* der = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: %s pem_file\n", argv[0]);
        return 2;
    }

    pem = read_file(argv[1], &pem_len);
    if (pem == NULL) {
        return 3;
    }

    fprintf(stderr, "[*] input PEM: %s\n", argv[1]);
    fprintf(stderr, "[*] input length: %ld\n", pem_len);
    fprintf(stderr, "[*] calling wc_PemToDer(type=CERT_TYPE)\n");

    ret = wc_PemToDer(pem, pem_len, CERT_TYPE, &der, NULL, NULL, NULL);

    fprintf(stderr, "[*] wc_PemToDer returned: %d\n", ret);
    fprintf(stderr, "[*] der pointer: %p\n", (void*)der);

    if (der != NULL) {
        wc_FreeDer(&der);
        fprintf(stderr, "[*] wc_FreeDer done\n");
    }

    free(pem);

    return ret == 0 ? 0 : 1;
}
