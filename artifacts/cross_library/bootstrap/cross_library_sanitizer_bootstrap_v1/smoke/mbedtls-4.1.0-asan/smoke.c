#include <stdio.h>
#include <mbedtls/version.h>
int main(void) {
    printf("SMOKE_RESULT target=mbedtls version_number=%lu\n", (unsigned long) MBEDTLS_VERSION_NUMBER);
    return MBEDTLS_VERSION_NUMBER == 0 ? 1 : 0;
}
