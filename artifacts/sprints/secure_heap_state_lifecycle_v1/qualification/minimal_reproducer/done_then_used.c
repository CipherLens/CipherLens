#include <openssl/crypto.h>
#include <stdio.h>

int main(void)
{
    printf("case=done_then_used\n");
    fflush(stdout);

    int init_ret = CRYPTO_secure_malloc_init(4096, 32);
    int done_ret = CRYPTO_secure_malloc_done();

    printf("CRYPTO_secure_malloc_init returned %d\n", init_ret);
    printf("CRYPTO_secure_malloc_done returned %d\n", done_ret);
    fflush(stdout);

    size_t used = CRYPTO_secure_used();

    printf("CRYPTO_secure_used returned %zu\n", used);
    return 0;
}
