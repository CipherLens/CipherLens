# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/rsa_x931_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
#include "testutil.h"

static OSSL_PROVIDER *prov_null = NULL;
static OSSL_LIB_CTX *libctx = NULL;

static int test_rsa_x931_keygen(void)
{
    int ret = 0;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;

    ret = TEST_ptr(rsa = ossl_rsa_new_with_ctx(libctx))
        && TEST_ptr(e = BN_new())
        && TEST_int_eq(BN_set_word(e, RSA_F4), 1)
        && TEST_int_eq(RSA_X931_generate_key_ex(rsa, 1024, e, NULL), 1);
    BN_free(e);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    if (!test_get_libctx(&libctx, &prov_null, NULL, NULL, NULL))
        return 0;

    ADD_TEST(test_rsa_x931_keygen);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(prov_null);
    OSSL_LIB_CTX_free(libctx);
}
```

## Call pattern 2

```c
static OSSL_PROVIDER *prov_null = NULL;
static OSSL_LIB_CTX *libctx = NULL;

static int test_rsa_x931_keygen(void)
{
    int ret = 0;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;

    ret = TEST_ptr(rsa = ossl_rsa_new_with_ctx(libctx))
        && TEST_ptr(e = BN_new())
        && TEST_int_eq(BN_set_word(e, RSA_F4), 1)
        && TEST_int_eq(RSA_X931_generate_key_ex(rsa, 1024, e, NULL), 1);
    BN_free(e);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    if (!test_get_libctx(&libctx, &prov_null, NULL, NULL, NULL))
        return 0;

    ADD_TEST(test_rsa_x931_keygen);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(prov_null);
    OSSL_LIB_CTX_free(libctx);
}
```

## Call pattern 3

```c
static OSSL_LIB_CTX *libctx = NULL;

static int test_rsa_x931_keygen(void)
{
    int ret = 0;
    BIGNUM *e = NULL;
    RSA *rsa = NULL;

    ret = TEST_ptr(rsa = ossl_rsa_new_with_ctx(libctx))
        && TEST_ptr(e = BN_new())
        && TEST_int_eq(BN_set_word(e, RSA_F4), 1)
        && TEST_int_eq(RSA_X931_generate_key_ex(rsa, 1024, e, NULL), 1);
    BN_free(e);
    RSA_free(rsa);
    return ret;
}

int setup_tests(void)
{
    if (!test_get_libctx(&libctx, &prov_null, NULL, NULL, NULL))
        return 0;

    ADD_TEST(test_rsa_x931_keygen);
    return 1;
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(prov_null);
    OSSL_LIB_CTX_free(libctx);
}
```

