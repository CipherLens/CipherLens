#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define PEM_BODY_CONTENT "[PEM_BODY]"

static const char malformed_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "Proc-Type: 4,ENCRYPTED\r\n"
    "DEK-Info: AES-128-CBC,AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB\r\n"
    "\r\n"
    PEM_BODY_CONTENT "\r\n"
    "-----END EC PRIVATE KEY-----\r\n";

static int poc_pem_pwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    const char *pwd = "pwd";
    int len = (int) strlen(pwd);
    (void) rwflag;
    (void) userdata;
    if (len > size) {
        len = size;
    }
    memcpy(buf, pwd, (size_t) len);
    return len;
}

int main(void)
{
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = 0;

    setbuf(stdout, NULL);

    printf("template_mutation PEM_BODY=%s\n", PEM_BODY_CONTENT);

    /*
     * Construct malformed encrypted PEM with short base64 body.
     * Source vulnerability: mbedTLS pem_check_pkcs_padding reads
     * input[input_len - 1] without checking input_len >= 1 when the
     * decoded buffer is empty. Oracle: ASAN heap-buffer-underflow or safe rejection.
     */
    bio = BIO_new_mem_buf(malformed_pem, -1);
    if (bio == NULL) {
        printf("[ERROR] BIO_new_mem_buf failed.\n");
        return 2;
    }

    printf("calling PEM_read_bio_PrivateKey with malformed encrypted PEM...\n");

    pkey = PEM_read_bio_PrivateKey(bio, NULL, poc_pem_pwd_cb, NULL);

    if (pkey == NULL) {
        printf("[OK] null_deref_dispatch: malformed encrypted PEM rejected safely by PEM_read_bio_PrivateKey.\n");
        ret = 0;
    } else {
        printf("[TRIAGE] crash_sanitizer_oracle: malformed encrypted PEM accepted unexpectedly.\n");
        EVP_PKEY_free(pkey);
        ret = 2;
    }

    BIO_free(bio);
    return ret;
}
