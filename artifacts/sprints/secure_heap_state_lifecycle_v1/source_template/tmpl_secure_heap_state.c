/*
 * Normalized source template for secure_heap_state_lifecycle.
 *
 * This is not a final case. The controlled renderer substitutes the state
 * sequence and oracle placeholders from render_matrix.yaml.
 */

#include <openssl/crypto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define SECURE_HEAP_INIT_API CRYPTO_secure_malloc_init
#define SECURE_HEAP_USED_API CRYPTO_secure_used
#define SECURE_HEAP_DONE_API CRYPTO_secure_malloc_done
#define SECURE_HEAP_INITIALIZED_CHECK_API CRYPTO_secure_malloc_initialized

CRASH_ORACLE

int main(void)
{
    setbuf(stdout, NULL);

    SECURE_HEAP_STATE_SEQUENCE

    return 0;
}
