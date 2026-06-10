#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>

/*
 * wolfSSL 3.10.2 does not define NID_localityName in the OpenSSL
 * compatibility headers, but wolfssl/wolfcrypt/asn.h defines:
 *
 * ASN_LOCALITY_NAME = 0x07
 *
 * wolfSSL_X509_NAME_get_text_by_NID() internally compares this NID
 * against ASN_LOCALITY_NAME, so using 0x07 directly is equivalent.
 */
#define POC_NID_LOCALITY_NAME 0x07

static unsigned char* read_file(const char* path, int* out_len)
{
    FILE* f;
    long sz;
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

    sz = ftell(f);
    if (sz <= 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }

    rewind(f);

    buf = (unsigned char*)malloc((size_t)sz);
    if (buf == NULL) {
        perror("malloc");
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        perror("fread");
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_len = (int)sz;
    return buf;
}

int main(int argc, char** argv)
{
    unsigned char* der = NULL;
    int der_len = 0;
    int nameSz = 0;

    WOLFSSL_X509* cert = NULL;
    WOLFSSL_X509_NAME* name = NULL;

    char localityName[80];

    if (argc != 2) {
        fprintf(stderr, "usage: %s <cert.der>\n", argv[0]);
        return 2;
    }

    wolfSSL_Init();

    der = read_file(argv[1], &der_len);
    if (der == NULL) {
        wolfSSL_Cleanup();
        return 3;
    }

    cert = wolfSSL_X509_d2i(&cert, der, der_len);
    if (cert == NULL) {
        fprintf(stderr, "wolfSSL_X509_d2i failed\n");
        free(der);
        wolfSSL_Cleanup();
        return 4;
    }

    name = wolfSSL_X509_get_subject_name(cert);
    if (name == NULL) {
        fprintf(stderr, "wolfSSL_X509_get_subject_name failed\n");
        wolfSSL_X509_free(cert);
        free(der);
        wolfSSL_Cleanup();
        return 5;
    }

    fprintf(stderr, "calling wolfSSL_X509_NAME_get_text_by_NID for localityName, nid=0x07\n");

    nameSz = wolfSSL_X509_NAME_get_text_by_NID(
        name,
        POC_NID_LOCALITY_NAME,
        localityName,
        sizeof(localityName)
    );

    printf("LOCALITY = %s (%d)\n", localityName, nameSz);

    wolfSSL_X509_free(cert);
    free(der);
    wolfSSL_Cleanup();

    return 0;
}
