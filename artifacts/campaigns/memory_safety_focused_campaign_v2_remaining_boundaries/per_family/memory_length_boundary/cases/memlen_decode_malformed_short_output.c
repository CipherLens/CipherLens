#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
int main(void) {
    unsigned char arena[320];
    unsigned char *out = arena;
    unsigned char in[96];
    unsigned char large[256];
    unsigned char key[16];
    unsigned char b64[] = "QUJDRA==";
    unsigned char bad64[] = "!!!!====";
    unsigned char pad64[] = "QQ======";
    const char *actual = "error";
    int ret = 0, outl = 0;
    unsigned int hmac_len = 0;
    unsigned char *hmacp = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *cipher = NULL;
    BIO *bio = NULL;
    BIGNUM *bn = NULL;
    memset(arena, 0xa5, sizeof(arena));
    memset(in, 0x41, sizeof(in));
    memset(large, 0x42, sizeof(large));
    memset(key, 0x11, sizeof(key));
    ret = EVP_DecodeBlock(out + 16, bad64, 8); actual = ret >= 0 ? "success" : "error";
    int canary_corrupted = 0;
    for (int i = 0; i < 16; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    for (int i = 48; i < 80; i++) if (arena[i] != 0xa5) canary_corrupted = 1;
    printf("ORACLE_EVENT family=memory_length_boundary\n");
    printf("ORACLE_EVENT case_id=memlen_decode_malformed_short_output\n");
    printf("ORACLE_EVENT expected_behavior=memory_safety_watch\n");
    printf("ORACLE_EVENT actual_behavior=%s\n", actual);
    printf("ORACLE_EVENT asan_observed=0\n");
    printf("ORACLE_EVENT ubsan_observed=0\n");
    printf("ORACLE_EVENT crash_signal=none\n");
    printf("ORACLE_EVENT canary_corrupted=%d\n", canary_corrupted);
    printf("ORACLE_EVENT candidate_label=%s\n", canary_corrupted ? "memory_safety_candidate" : "no_candidate");
    return 0;
}
