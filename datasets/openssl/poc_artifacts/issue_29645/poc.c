#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(void)
{
    BIO *bio = NULL;
    void *original_data = NULL;
    void *observed_data = NULL;
    const char message[] = "semantic seed BIO_set_data harness";
    int written;
    int ret = 1;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        fprintf(stderr, "BIO_new(BIO_s_mem()) failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    written = BIO_write(bio, message, (int)strlen(message));
    if (written <= 0) {
        fprintf(stderr, "BIO_write failed\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    original_data = BIO_get_data(bio);
    BIO_set_data(bio, original_data);
    observed_data = BIO_get_data(bio);

    printf("BIO_get_data before set: %p\n", original_data);
    printf("BIO_get_data after set:  %p\n", observed_data);
    if (observed_data != original_data) {
        fprintf(stderr, "BIO_set_data did not preserve the expected data pointer\n");
        goto end;
    }

    ret = 0;

end:
    BIO_free(bio);
    return ret;
}
