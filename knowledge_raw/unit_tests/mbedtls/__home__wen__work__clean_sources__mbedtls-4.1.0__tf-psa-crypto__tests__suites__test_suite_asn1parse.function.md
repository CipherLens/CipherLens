# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_asn1parse.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
*p = start;
            ret = mbedtls_asn1_get_bool(p, end, &val);
            if (ret == 0) {
                TEST_ASSERT(val == 0 || val == 1);
            }
            break;
        }

        case MBEDTLS_ASN1_INTEGER:
        {
#if defined(MBEDTLS_BIGNUM_C)
            mbedtls_mpi mpi;
            mbedtls_mpi_init(&mpi);
            *p = start;
            ret = mbedtls_asn1_get_mpi(p, end, &mpi);
            mbedtls_mpi_free(&mpi);
#else
            *p = start + 1;
            ret = mbedtls_asn1_get_len(p, end, &len);
            *p += len;
#endif
            /* If we're sure that the number fits in an int, also
             * call mbedtls_asn1_get_int(). */
            if (ret == 0 && len < sizeof(int)) {
                int val = -257;
                unsigned char *q = start;
                ret = mbedtls_asn1_get_int(&q, end, &val);
                TEST_ASSERT(*p == q);
            }
            break;
        }

        case MBEDTLS_ASN1_BIT_STRING:
        {
            mbedtls_asn1_bitstring bs;
            *p = start;
            ret = mbedtls_asn1_get_bitstring(p, end, &bs);
            break;
        }
```

## Call pattern 2

```c
TEST_ASSERT(val == 0 || val == 1);
            }
            break;
        }

        case MBEDTLS_ASN1_INTEGER:
        {
#if defined(MBEDTLS_BIGNUM_C)
            mbedtls_mpi mpi;
            mbedtls_mpi_init(&mpi);
            *p = start;
            ret = mbedtls_asn1_get_mpi(p, end, &mpi);
            mbedtls_mpi_free(&mpi);
#else
            *p = start + 1;
            ret = mbedtls_asn1_get_len(p, end, &len);
            *p += len;
#endif
            /* If we're sure that the number fits in an int, also
             * call mbedtls_asn1_get_int(). */
            if (ret == 0 && len < sizeof(int)) {
                int val = -257;
                unsigned char *q = start;
                ret = mbedtls_asn1_get_int(&q, end, &val);
                TEST_ASSERT(*p == q);
            }
            break;
        }

        case MBEDTLS_ASN1_BIT_STRING:
        {
            mbedtls_asn1_bitstring bs;
            *p = start;
            ret = mbedtls_asn1_get_bitstring(p, end, &bs);
            break;
        }

        case MBEDTLS_ASN1_SEQUENCE:
        {
            while (*p <= end && *p < content_start + len && ret == 0) {
```

## Call pattern 3

```c
/* END_CASE */

/* BEGIN_CASE */
void empty_integer(const data_t *input)
{
    unsigned char *p;
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi actual_mpi;
#endif
    int val;

#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_init(&actual_mpi);
#endif

    /* An INTEGER with no content is not valid. */
    p = input->x;
    TEST_EQUAL(mbedtls_asn1_get_int(&p, input->x + input->len, &val),
               MBEDTLS_ERR_ASN1_INVALID_LENGTH);

#if defined(MBEDTLS_BIGNUM_C)
    /* INTEGERs are sometimes abused as bitstrings, so the library accepts
     * an INTEGER with empty content and gives it the value 0. */
    p = input->x;
    TEST_EQUAL(mbedtls_asn1_get_mpi(&p, input->x + input->len, &actual_mpi),
               0);
    TEST_EQUAL(mbedtls_mpi_cmp_int(&actual_mpi, 0), 0);
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&actual_mpi);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
void get_integer(const data_t *input,
                 const char *expected_hex, int expected_result)
```

## Call pattern 4

```c
#if defined(MBEDTLS_BIGNUM_C)
    /* INTEGERs are sometimes abused as bitstrings, so the library accepts
     * an INTEGER with empty content and gives it the value 0. */
    p = input->x;
    TEST_EQUAL(mbedtls_asn1_get_mpi(&p, input->x + input->len, &actual_mpi),
               0);
    TEST_EQUAL(mbedtls_mpi_cmp_int(&actual_mpi, 0), 0);
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&actual_mpi);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
void get_integer(const data_t *input,
                 const char *expected_hex, int expected_result)
{
    unsigned char *p;
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi expected_mpi;
    mbedtls_mpi actual_mpi;
    mbedtls_mpi complement;
    int expected_result_for_mpi = expected_result;
#endif
    long expected_value;
    int expected_result_for_int = expected_result;
    int val;
    int ret;

#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_init(&expected_mpi);
    mbedtls_mpi_init(&actual_mpi);
    mbedtls_mpi_init(&complement);
#endif
```

## Call pattern 5

```c
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi expected_mpi;
    mbedtls_mpi actual_mpi;
    mbedtls_mpi complement;
    int expected_result_for_mpi = expected_result;
#endif
    long expected_value;
    int expected_result_for_int = expected_result;
    int val;
    int ret;

#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_init(&expected_mpi);
    mbedtls_mpi_init(&actual_mpi);
    mbedtls_mpi_init(&complement);
#endif

    errno = 0;
    expected_value = strtol(expected_hex, NULL, 16);
    if (expected_result == 0 &&
        (errno == ERANGE
#if LONG_MAX > INT_MAX
         || expected_value > INT_MAX || expected_value < INT_MIN
#endif
        )) {
        /* The library returns the dubious error code INVALID_LENGTH
         * for integers that are out of range. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    if (expected_result == 0 && expected_value < 0) {
        /* The library does not support negative INTEGERs and
         * returns the dubious error code INVALID_LENGTH.
         * Test that we preserve the historical behavior. If we
         * decide to change the behavior, we'll also change this test. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    p = input->x;
    ret = mbedtls_asn1_get_int(&p, input->x + input->len, &val);
    TEST_EQUAL(ret, expected_result_for_int);
```

## Call pattern 6

```c
mbedtls_mpi expected_mpi;
    mbedtls_mpi actual_mpi;
    mbedtls_mpi complement;
    int expected_result_for_mpi = expected_result;
#endif
    long expected_value;
    int expected_result_for_int = expected_result;
    int val;
    int ret;

#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_init(&expected_mpi);
    mbedtls_mpi_init(&actual_mpi);
    mbedtls_mpi_init(&complement);
#endif

    errno = 0;
    expected_value = strtol(expected_hex, NULL, 16);
    if (expected_result == 0 &&
        (errno == ERANGE
#if LONG_MAX > INT_MAX
         || expected_value > INT_MAX || expected_value < INT_MIN
#endif
        )) {
        /* The library returns the dubious error code INVALID_LENGTH
         * for integers that are out of range. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    if (expected_result == 0 && expected_value < 0) {
        /* The library does not support negative INTEGERs and
         * returns the dubious error code INVALID_LENGTH.
         * Test that we preserve the historical behavior. If we
         * decide to change the behavior, we'll also change this test. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    p = input->x;
    ret = mbedtls_asn1_get_int(&p, input->x + input->len, &val);
    TEST_EQUAL(ret, expected_result_for_int);
    if (ret == 0) {
```

## Call pattern 7

```c
mbedtls_mpi actual_mpi;
    mbedtls_mpi complement;
    int expected_result_for_mpi = expected_result;
#endif
    long expected_value;
    int expected_result_for_int = expected_result;
    int val;
    int ret;

#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_init(&expected_mpi);
    mbedtls_mpi_init(&actual_mpi);
    mbedtls_mpi_init(&complement);
#endif

    errno = 0;
    expected_value = strtol(expected_hex, NULL, 16);
    if (expected_result == 0 &&
        (errno == ERANGE
#if LONG_MAX > INT_MAX
         || expected_value > INT_MAX || expected_value < INT_MIN
#endif
        )) {
        /* The library returns the dubious error code INVALID_LENGTH
         * for integers that are out of range. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }
    if (expected_result == 0 && expected_value < 0) {
        /* The library does not support negative INTEGERs and
         * returns the dubious error code INVALID_LENGTH.
         * Test that we preserve the historical behavior. If we
         * decide to change the behavior, we'll also change this test. */
        expected_result_for_int = MBEDTLS_ERR_ASN1_INVALID_LENGTH;
    }

    p = input->x;
    ret = mbedtls_asn1_get_int(&p, input->x + input->len, &val);
    TEST_EQUAL(ret, expected_result_for_int);
    if (ret == 0) {
        TEST_EQUAL(val, expected_value);
```

## Call pattern 8

```c
* abused as bit strings), so the result of parsing them
             * is a positive integer such that expected_mpi +
             * actual_mpi = 2^n where n is the length of the content
             * of the INTEGER. (Leading ff octets don't matter for the
             * expected value, but they matter for the actual value.)
             * Test that we don't change from this behavior. If we
             * decide to fix the library to change the behavior on
             * negative INTEGERs, we'll fix this test code. */
            unsigned char *q = input->x + 1;
            size_t len;
            TEST_ASSERT(mbedtls_asn1_get_len(&q, input->x + input->len,
                                             &len) == 0);
            TEST_ASSERT(mbedtls_mpi_lset(&complement, 1) == 0);
            TEST_ASSERT(mbedtls_mpi_shift_l(&complement, len * 8) == 0);
            TEST_ASSERT(mbedtls_mpi_add_mpi(&complement, &complement,
                                            &expected_mpi) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&complement,
                                            &actual_mpi) == 0);
        }
        TEST_ASSERT(p == input->x + input->len);
    }
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&expected_mpi);
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_mpi_free(&complement);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
/**
 * The #asn1_data_length argument is only used to provide real data length,
 * not the buffer length, in case there are more bytes in the buffer, than there
 * is data, it is then compared with the difference of initial p, and p after the
 * #mbedtls_asn1_get_integer() call
 */
```

## Call pattern 9

```c
TEST_ASSERT(mbedtls_mpi_shift_l(&complement, len * 8) == 0);
            TEST_ASSERT(mbedtls_mpi_add_mpi(&complement, &complement,
                                            &expected_mpi) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&complement,
                                            &actual_mpi) == 0);
        }
        TEST_ASSERT(p == input->x + input->len);
    }
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&expected_mpi);
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_mpi_free(&complement);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
/**
 * The #asn1_data_length argument is only used to provide real data length,
 * not the buffer length, in case there are more bytes in the buffer, than there
 * is data, it is then compared with the difference of initial p, and p after the
 * #mbedtls_asn1_get_integer() call
 */
void get_integer_raw(const data_t *input,
                     const data_t *expected_output, int expected_result,
                     int asn1_data_length)
{
    int ret;
    unsigned char *p = input->x;

    if (asn1_data_length == -1) {
        asn1_data_length = input->len;
    }

    /* Initialize pointer and length to nonsense values so that we can
     * distinguish leaving them unchanged from setting them in the error
```

## Call pattern 10

```c
TEST_ASSERT(mbedtls_mpi_add_mpi(&complement, &complement,
                                            &expected_mpi) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&complement,
                                            &actual_mpi) == 0);
        }
        TEST_ASSERT(p == input->x + input->len);
    }
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&expected_mpi);
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_mpi_free(&complement);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
/**
 * The #asn1_data_length argument is only used to provide real data length,
 * not the buffer length, in case there are more bytes in the buffer, than there
 * is data, it is then compared with the difference of initial p, and p after the
 * #mbedtls_asn1_get_integer() call
 */
void get_integer_raw(const data_t *input,
                     const data_t *expected_output, int expected_result,
                     int asn1_data_length)
{
    int ret;
    unsigned char *p = input->x;

    if (asn1_data_length == -1) {
        asn1_data_length = input->len;
    }

    /* Initialize pointer and length to nonsense values so that we can
     * distinguish leaving them unchanged from setting them in the error
     * case. */
```

## Call pattern 11

```c
&expected_mpi) == 0);
            TEST_ASSERT(mbedtls_mpi_cmp_mpi(&complement,
                                            &actual_mpi) == 0);
        }
        TEST_ASSERT(p == input->x + input->len);
    }
#endif

exit:
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_mpi_free(&expected_mpi);
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_mpi_free(&complement);
#endif
    /*empty cleanup in some configurations*/;
}
/* END_CASE */

/* BEGIN_CASE */
/**
 * The #asn1_data_length argument is only used to provide real data length,
 * not the buffer length, in case there are more bytes in the buffer, than there
 * is data, it is then compared with the difference of initial p, and p after the
 * #mbedtls_asn1_get_integer() call
 */
void get_integer_raw(const data_t *input,
                     const data_t *expected_output, int expected_result,
                     int asn1_data_length)
{
    int ret;
    unsigned char *p = input->x;

    if (asn1_data_length == -1) {
        asn1_data_length = input->len;
    }

    /* Initialize pointer and length to nonsense values so that we can
     * distinguish leaving them unchanged from setting them in the error
     * case. */
    unsigned char dummy = 0;
```

## Call pattern 12

```c
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_BIGNUM_C */
void get_mpi_too_large()
{
    unsigned char *buf = NULL;
    unsigned char *p;
    mbedtls_mpi actual_mpi;
    size_t too_many_octets =
        MBEDTLS_MPI_MAX_LIMBS * sizeof(mbedtls_mpi_uint) + 1;
    size_t size = too_many_octets + 6;

    mbedtls_mpi_init(&actual_mpi);

    TEST_CALLOC(buf, size);
    buf[0] = 0x02; /* tag: INTEGER */
    buf[1] = 0x84; /* 4-octet length */
    buf[2] = (too_many_octets >> 24) & 0xff;
    buf[3] = (too_many_octets >> 16) & 0xff;
    buf[4] = (too_many_octets >> 8) & 0xff;
    buf[5] = too_many_octets & 0xff;
    buf[6] = 0x01; /* most significant octet */

    p = buf;
    TEST_EQUAL(mbedtls_asn1_get_mpi(&p, buf + size, &actual_mpi),
               MBEDTLS_ERR_MPI_ALLOC_FAILED);

exit:
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_free(buf);
}
/* END_CASE */

/* BEGIN_CASE */
void get_bitstring(const data_t *input,
                   int expected_length, int expected_unused_bits,
                   int expected_result, int expected_result_null)
{
    mbedtls_asn1_bitstring bs = { 0xdead, 0x21, NULL };
    unsigned char *p = input->x;
```

## Call pattern 13

```c
buf[1] = 0x84; /* 4-octet length */
    buf[2] = (too_many_octets >> 24) & 0xff;
    buf[3] = (too_many_octets >> 16) & 0xff;
    buf[4] = (too_many_octets >> 8) & 0xff;
    buf[5] = too_many_octets & 0xff;
    buf[6] = 0x01; /* most significant octet */

    p = buf;
    TEST_EQUAL(mbedtls_asn1_get_mpi(&p, buf + size, &actual_mpi),
               MBEDTLS_ERR_MPI_ALLOC_FAILED);

exit:
    mbedtls_mpi_free(&actual_mpi);
    mbedtls_free(buf);
}
/* END_CASE */

/* BEGIN_CASE */
void get_bitstring(const data_t *input,
                   int expected_length, int expected_unused_bits,
                   int expected_result, int expected_result_null)
{
    mbedtls_asn1_bitstring bs = { 0xdead, 0x21, NULL };
    unsigned char *p = input->x;

    TEST_EQUAL(mbedtls_asn1_get_bitstring(&p, input->x + input->len, &bs),
               expected_result);
    if (expected_result == 0) {
        TEST_EQUAL(bs.len, (size_t) expected_length);
        TEST_EQUAL(bs.unused_bits, expected_unused_bits);
        TEST_ASSERT(bs.p != NULL);
        TEST_EQUAL(bs.p - input->x + bs.len, input->len);
        TEST_ASSERT(p == input->x + input->len);
    }

    p = input->x;
    TEST_EQUAL(mbedtls_asn1_get_bitstring_null(&p, input->x + input->len,
                                               &bs.len),
               expected_result_null);
    if (expected_result_null == 0) {
```

