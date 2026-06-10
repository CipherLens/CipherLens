#include <stdio.h>
#include <stdlib.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/misc.h>

#include "tests/utils.h"

#ifndef WOLFSSL_DTLS13
#error "WOLFSSL_DTLS13 is required"
#endif

#ifndef HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES
#error "HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES is required"
#endif

#define ACK_RECORDS 4097



static w64wrapper make_w64(word32 hi, word32 lo)
{
    w64wrapper x;
    XMEMSET(&x, 0, sizeof(x));

#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_W64_WRAPPER_TEST)
    x.n = ((word64)hi << 32) | lo;
#else
    x.n[0] = hi;
    x.n[1] = lo;
#endif

    return x;
}

int main(void)
{
    WOLFSSL_CTX* ctx_c = NULL;
    WOLFSSL_CTX* ctx_s = NULL;
    WOLFSSL* ssl_c = NULL;
    WOLFSSL* ssl_s = NULL;
    struct test_memio_ctx test_ctx;
    unsigned char readBuf[50];
    word32 length = 0;
    int ret;
    int i;

    wolfSSL_Init();

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    fprintf(stderr, "[*] setting up DTLS 1.3 manual memio context\n");

    ret = test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
        wolfDTLSv1_3_client_method, wolfDTLSv1_3_server_method);
    if (ret != 0) {
        fprintf(stderr, "[-] test_memio_setup failed: %d\n", ret);
        return 2;
    }

    fprintf(stderr, "[*] doing DTLS 1.3 handshake\n");

    ret = test_memio_do_handshake(ssl_c, ssl_s, 10, NULL);
    if (ret != 0) {
        fprintf(stderr, "[-] test_memio_do_handshake failed: %d\n", ret);
        return 3;
    }

    ret = wolfSSL_read(ssl_c, readBuf, sizeof(readBuf));
    fprintf(stderr, "[*] wolfSSL_read client ret: %d, err: %d\n",
            ret, wolfSSL_get_error(ssl_c, ret));

    ret = wolfSSL_read(ssl_s, readBuf, sizeof(readBuf));
    fprintf(stderr, "[*] wolfSSL_read server ret: %d, err: %d\n",
            ret, wolfSSL_get_error(ssl_s, ret));

    fprintf(stderr, "[*] adding %d DTLS 1.3 ACK records\n", ACK_RECORDS);

    for (i = 0; i < ACK_RECORDS; i++) {
        ret = Dtls13RtxAddAck(ssl_c, make_w64(0, 1),
                              make_w64(0, (word32)i));
        if (ret != 0) {
            fprintf(stderr, "[-] Dtls13RtxAddAck failed at i=%d ret=%d\n",
                    i, ret);
            return 4;
        }
    }

    fprintf(stderr, "[*] calling Dtls13WriteAckMessage\n");

    ret = Dtls13WriteAckMessage(ssl_c, ssl_c->dtls13Rtx.seenRecords, &length);

    fprintf(stderr, "[*] Dtls13WriteAckMessage returned: %d\n", ret);
    fprintf(stderr, "[*] encoded ACK length: %u\n", length);

    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_c);
    wolfSSL_free(ssl_s);
    wolfSSL_CTX_free(ctx_s);

    wolfSSL_Cleanup();

    return ret == 0 ? 0 : 1;
}
