#include "openssl/bio.h"

void example1(void)
{
    BIO* bio;
    bio = BIO_new(BIO_s_secmem());
    if (!CRYPTO_secure_malloc_init(4096, 1)) {
        return;
    }
    if ( bio == NULL ) {
        return;
    }
    /* Allocates 8 bytes of secure heap */
    BIO_write(bio, "\0\0\0", 3);
}
void example2(void)
{
    BIO* bio;
    bio = BIO_new(BIO_s_secmem());
    if (!CRYPTO_secure_malloc_init(4096, 2)) {
        return;
    }
    if ( bio == NULL ) {
        return;
    }
    /* Allocates 4 bytes of secure heap */
    BIO_write(bio, "\0", 1);
}
int main(void)
{
    /* example1(); */
    /* example2(); */

    return 0;
}
