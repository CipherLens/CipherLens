#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_port.h>
int main(void) {
    unsigned char out[WC_SHA256_DIGEST_SIZE];
    const unsigned char msg[] = "abc";
    int ret = wolfCrypt_Init();
    if (ret == 0)
        ret = wc_Sha256Hash(msg, sizeof(msg) - 1, out);
    wolfCrypt_Cleanup();
    printf("SMOKE_RESULT target=wolfssl ret=%d out0=%u\n", ret, (unsigned)out[0]);
    return ret == 0 ? 0 : 1;
}
