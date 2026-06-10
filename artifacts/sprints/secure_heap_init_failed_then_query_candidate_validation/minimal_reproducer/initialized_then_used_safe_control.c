#include <openssl/crypto.h>
#include <stdio.h>

int main(void)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("case_id=initialized_then_used_safe_control\n");
    printf("OpenSSL_version=%s\n", OpenSSL_version(OPENSSL_VERSION));

    int init_ret = CRYPTO_secure_malloc_init(4096, 32);
    printf("CRYPTO_secure_malloc_init(4096, 32)=%d\n", init_ret);
    printf("CRYPTO_secure_malloc_initialized()=%d\n", CRYPTO_secure_malloc_initialized());
    if (init_ret == 0) {
        printf("HARNESS_ERROR=init_failed\n");
        return 2;
    }

    size_t used = CRYPTO_secure_used();
    printf("CRYPTO_secure_used()=%zu\n", used);

    int done_ret = CRYPTO_secure_malloc_done();
    printf("CRYPTO_secure_malloc_done()=%d\n", done_ret);
    return 0;
}
