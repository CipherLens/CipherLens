/*
 * Family-level canonical wolfSSL template.
 *
 * family: pkcs_container_parsing
 * seed evidence: WOLFSSL-POC-0007 and WOLFSSL-POC-0006
 *
 * This file is a source-library canonical template, not a runnable PoC claim.
 * Mutation planners bind slots such as [CONTAINER_BYTES], [ATTRIBUTE_COUNT],
 * [CONTAINER_FORMAT], [TRAILING_BYTES], and [EXPECT_RET].
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef FAMILY_PKCS_MODE
#define FAMILY_PKCS_MODE 1 /* [CONTAINER_OPERATION]: 1=decode_enveloped, 2=encode_signed */
#endif

#ifndef FAMILY_ATTRIBUTE_COUNT
#define FAMILY_ATTRIBUTE_COUNT 8 /* [ATTRIBUTE_COUNT] */
#endif

static int family_ori_decrypt_cb(wc_PKCS7* pkcs7,
    byte* ori_type, word32 ori_type_sz,
    byte* ori_value, word32 ori_value_sz,
    byte* decrypted_key, word32* decrypted_key_sz,
    void* ctx)
{
    (void)pkcs7;
    (void)ori_type;
    (void)ori_type_sz;
    (void)ori_value;
    (void)ori_value_sz;
    (void)decrypted_key;
    (void)decrypted_key_sz;
    (void)ctx;
    return -1;
}

static int family_decode_container_path(void)
{
    wc_PKCS7* p7 = NULL;
    byte out[256];
    int ret;

    static const byte container_bytes[] = {
        0x30, 0x06, 0x06, 0x01, 0x2a, 0x04, 0x01, 0x00
        /* [CONTAINER_BYTES] */
    };
    static const byte trailing_bytes[] = { 0x00 /* [TRAILING_BYTES] */ };

    memset(out, 0, sizeof(out));
    p7 = wc_PKCS7_New(NULL, INVALID_DEVID);
    if (p7 == NULL)
        return 2;

    wc_PKCS7_SetOriDecryptCb(p7, family_ori_decrypt_cb);

    /* trigger_call: preserve PKCS container parse/decode semantics. */
    ret = wc_PKCS7_DecodeEnvelopedData(p7, (byte*)container_bytes,
        (word32)(sizeof(container_bytes) + 0 * sizeof(trailing_bytes)),
        out, (word32)sizeof(out));

    /* oracle_check: return-code/sanitizer/full-consumption classification. */
    if (ret == 0) {
        wc_PKCS7_Free(p7);
        return 10; /* [EXPECT_RET] */
    }

    wc_PKCS7_Free(p7); /* cleanup_call */
    return 0;
}

static int family_encode_signed_path(void)
{
    wc_PKCS7 pkcs7;
    byte out[4096];
    byte content[] = "family-level PKCS7 SignedData control";
    PKCS7Attrib attrs[FAMILY_ATTRIBUTE_COUNT];
    byte oid_body[] = { 0x2a, 0x03, 0x01 /* [ATTRIBUTE_OID_BYTES] */ };
    byte value_body[] = { 0x13, 0x01, '1' /* [ATTRIBUTE_VALUE_BYTES] */ };
    int ret;

    memset(&pkcs7, 0, sizeof(pkcs7));
    memset(&attrs, 0, sizeof(attrs));
    memset(out, 0, sizeof(out));

    ret = wc_PKCS7_Init(&pkcs7, NULL, 0);
    if (ret != 0)
        goto cleanup;

    attrs[0].oid = oid_body;
    attrs[0].oidSz = (word32)sizeof(oid_body);
    attrs[0].value = value_body;
    attrs[0].valueSz = (word32)sizeof(value_body);

    pkcs7.content = content;
    pkcs7.contentSz = (word32)sizeof(content);
    pkcs7.signedAttribs = attrs;
    pkcs7.signedAttribsSz = (word32)(sizeof(attrs) / sizeof(attrs[0]));

    /* trigger_call: preserve signed-attribute encoding boundary semantics. */
    ret = wc_PKCS7_EncodeSignedData(&pkcs7, out, (word32)sizeof(out));

    /* oracle_check: return-code/sanitizer classification, not a crash claim. */
    if (ret > 0) {
        wc_PKCS7_Free(&pkcs7);
        return 11; /* [EXPECT_RET] */
    }

cleanup:
    wc_PKCS7_Free(&pkcs7); /* cleanup_call */
    return 0;
}

int main(void)
{
#if FAMILY_PKCS_MODE == 2
    return family_encode_signed_path();
#else
    return family_decode_container_path();
#endif
}
