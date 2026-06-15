#include <stdio.h>
#include <stddef.h>

#include <wolfssl/options.h>
#include <wolfssl/internal.h>

int main(void)
{
    size_t cert_sz = sizeof(Cert);
    size_t akid_off = offsetof(Cert, akid);
    size_t akid_sz = sizeof(((Cert*)0)->akid);

    printf("sizeof(Cert) = %zu\n", cert_sz);
    printf("offsetof(Cert, akid) = %zu\n", akid_off);
    printf("sizeof(Cert.akid) = %zu\n", akid_sz);
    printf("bytes from akid start to Cert end = %zu\n", cert_sz - akid_off);
    printf("minimum copy length to exceed Cert object = %zu\n", cert_sz - akid_off + 1);

    return 0;
}
