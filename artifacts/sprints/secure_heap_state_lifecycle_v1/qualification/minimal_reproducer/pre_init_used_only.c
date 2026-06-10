#include <openssl/crypto.h>
#include <stdio.h>

int main(void)
{
    printf("case=pre_init_used_only\n");
    fflush(stdout);

    size_t used = CRYPTO_secure_used();

    printf("CRYPTO_secure_used returned %zu\n", used);
    return 0;
}
