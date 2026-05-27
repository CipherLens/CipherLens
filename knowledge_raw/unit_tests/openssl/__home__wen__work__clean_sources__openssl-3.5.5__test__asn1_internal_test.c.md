# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/asn1_internal_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
***/

#include <openssl/rsa.h>

static int test_empty_nonoptional_content(void)
{
    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int ok = 0;

    if (!TEST_ptr(rsa = RSA_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_true(RSA_set0_key(rsa, n, e, NULL)))
        goto end;

    n = e = NULL; /* They are now "owned" by |rsa| */

    /*
     * This SHOULD fail, as we're trying to encode a public key as a private
     * key.  The private key bits MUST be present for a proper RSAPrivateKey.
     */
    if (TEST_int_le(i2d_RSAPrivateKey(rsa, NULL), 0))
        ok = 1;

end:
    RSA_free(rsa);
    BN_free(n);
    BN_free(e);
    return ok;
}

/**********************************************************************
 *
 * Tests of the Unicode code point range
 *
 ***/

static int test_unicode(const unsigned char *univ, size_t len, int expected)
```

## Call pattern 2

```c
#include <openssl/rsa.h>

static int test_empty_nonoptional_content(void)
{
    RSA *rsa = NULL;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    int ok = 0;

    if (!TEST_ptr(rsa = RSA_new())
        || !TEST_ptr(n = BN_new())
        || !TEST_ptr(e = BN_new())
        || !TEST_true(RSA_set0_key(rsa, n, e, NULL)))
        goto end;

    n = e = NULL; /* They are now "owned" by |rsa| */

    /*
     * This SHOULD fail, as we're trying to encode a public key as a private
     * key.  The private key bits MUST be present for a proper RSAPrivateKey.
     */
    if (TEST_int_le(i2d_RSAPrivateKey(rsa, NULL), 0))
        ok = 1;

end:
    RSA_free(rsa);
    BN_free(n);
    BN_free(e);
    return ok;
}

/**********************************************************************
 *
 * Tests of the Unicode code point range
 *
 ***/

static int test_unicode(const unsigned char *univ, size_t len, int expected)
{
```

## Call pattern 3

```c
n = e = NULL; /* They are now "owned" by |rsa| */

    /*
     * This SHOULD fail, as we're trying to encode a public key as a private
     * key.  The private key bits MUST be present for a proper RSAPrivateKey.
     */
    if (TEST_int_le(i2d_RSAPrivateKey(rsa, NULL), 0))
        ok = 1;

end:
    RSA_free(rsa);
    BN_free(n);
    BN_free(e);
    return ok;
}

/**********************************************************************
 *
 * Tests of the Unicode code point range
 *
 ***/

static int test_unicode(const unsigned char *univ, size_t len, int expected)
{
    const unsigned char *end = univ + len;
    int ok = 1;

    for (; univ < end; univ += 4) {
        if (!TEST_int_eq(ASN1_mbstring_copy(NULL, univ, 4, MBSTRING_UNIV,
                             B_ASN1_UTF8STRING),
                expected))
            ok = 0;
    }
    return ok;
}

static int test_unicode_range(void)
{
    const unsigned char univ_ok[] = "\0\0\0\0"
```

## Call pattern 4

```c
n = e = NULL; /* They are now "owned" by |rsa| */

    /*
     * This SHOULD fail, as we're trying to encode a public key as a private
     * key.  The private key bits MUST be present for a proper RSAPrivateKey.
     */
    if (TEST_int_le(i2d_RSAPrivateKey(rsa, NULL), 0))
        ok = 1;

end:
    RSA_free(rsa);
    BN_free(n);
    BN_free(e);
    return ok;
}

/**********************************************************************
 *
 * Tests of the Unicode code point range
 *
 ***/

static int test_unicode(const unsigned char *univ, size_t len, int expected)
{
    const unsigned char *end = univ + len;
    int ok = 1;

    for (; univ < end; univ += 4) {
        if (!TEST_int_eq(ASN1_mbstring_copy(NULL, univ, 4, MBSTRING_UNIV,
                             B_ASN1_UTF8STRING),
                expected))
            ok = 0;
    }
    return ok;
}

static int test_unicode_range(void)
{
    const unsigned char univ_ok[] = "\0\0\0\0"
                                    "\0\0\xd7\xff"
```

