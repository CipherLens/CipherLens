#include <openssl/crypto.h>
#include <stdio.h>

int main(void)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("case_id=init_failed_then_used\n");
    printf("OpenSSL_version=%s\n", OpenSSL_version(OPENSSL_VERSION));

    int init_ret = CRYPTO_secure_malloc_init(16, 16);
    printf("CRYPTO_secure_malloc_init(16, 16)=%d\n", init_ret);
    printf("CRYPTO_secure_malloc_initialized()=%d\n", CRYPTO_secure_malloc_initialized());
    printf("about_to_call=CRYPTO_secure_used\n");

    size_t used = CRYPTO_secure_used();
    printf("CRYPTO_secure_used()=%zu\n", used);
    return 0;
}
