#include <openssl/crypto.h>
int main(){
    // Call without initializing the secure heap
    size_t u = CRYPTO_secure_used();
    (void)u;
    return 0;
}


