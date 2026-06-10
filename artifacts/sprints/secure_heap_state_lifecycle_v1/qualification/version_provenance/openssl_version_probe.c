#include <stdio.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>

int main(void)
{
    printf("OPENSSL_VERSION_TEXT(header): %s\n", OPENSSL_VERSION_TEXT);
    printf("OpenSSL_version(runtime): %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL_version_num(runtime): %lx\n", OpenSSL_version_num());
#ifdef OPENSSL_FULL_VERSION_STRING
    printf("OpenSSL_full_version(runtime): %s\n", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
#endif
    return 0;
}
