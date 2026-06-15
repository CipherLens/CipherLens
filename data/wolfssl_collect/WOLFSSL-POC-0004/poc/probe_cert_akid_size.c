#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/internal.h>

int main(void)
{
    printf("sizeof(Cert) = %zu\n", sizeof(Cert));
    printf("sizeof(Cert.akid) = %zu\n", sizeof(((Cert*)0)->akid));
    return 0;
}
