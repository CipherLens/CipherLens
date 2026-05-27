# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_asn1write.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
exit:
    mbedtls_free(data.output);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_BIGNUM_C */
void mbedtls_asn1_write_mpi(data_t *val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    mbedtls_mpi mpi, read;
    int ret;

    mbedtls_mpi_init(&mpi);
    mbedtls_mpi_init(&read);
    TEST_ASSERT(mbedtls_mpi_read_binary(&mpi, val->x, val->len) == 0);

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_mpi(&data.p, data.start, &mpi);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            TEST_EQUAL(mbedtls_asn1_get_mpi(&data.p, data.end, &read), 0);
            TEST_EQUAL(0, mbedtls_mpi_cmp_mpi(&mpi, &read));
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_mpi_free(&mpi);
    mbedtls_mpi_free(&read);
    mbedtls_free(data.output);
```

## Call pattern 2

```c
mbedtls_free(data.output);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_BIGNUM_C */
void mbedtls_asn1_write_mpi(data_t *val, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    mbedtls_mpi mpi, read;
    int ret;

    mbedtls_mpi_init(&mpi);
    mbedtls_mpi_init(&read);
    TEST_ASSERT(mbedtls_mpi_read_binary(&mpi, val->x, val->len) == 0);

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        ret = mbedtls_asn1_write_mpi(&data.p, data.start, &mpi);
        if (!generic_write_finish_step(&data, expected, ret)) {
            goto exit;
        }
#if defined(MBEDTLS_ASN1_PARSE_C)
        if (ret >= 0) {
            TEST_EQUAL(mbedtls_asn1_get_mpi(&data.p, data.end, &read), 0);
            TEST_EQUAL(0, mbedtls_mpi_cmp_mpi(&mpi, &read));
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_mpi_free(&mpi);
    mbedtls_mpi_free(&read);
    mbedtls_free(data.output);
}
```

## Call pattern 3

```c
if (ret >= 0) {
            TEST_EQUAL(mbedtls_asn1_get_mpi(&data.p, data.end, &read), 0);
            TEST_EQUAL(0, mbedtls_mpi_cmp_mpi(&mpi, &read));
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_mpi_free(&mpi);
    mbedtls_mpi_free(&read);
    mbedtls_free(data.output);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_asn1_write_string(int tag, data_t *content, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        switch (tag) {
            case MBEDTLS_ASN1_OCTET_STRING:
                ret = mbedtls_asn1_write_octet_string(
                    &data.p, data.start, content->x, content->len);
                break;
            case MBEDTLS_ASN1_OID:
                ret = mbedtls_asn1_write_oid(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            case MBEDTLS_ASN1_UTF8_STRING:
                ret = mbedtls_asn1_write_utf8_string(
```

## Call pattern 4

```c
TEST_EQUAL(mbedtls_asn1_get_mpi(&data.p, data.end, &read), 0);
            TEST_EQUAL(0, mbedtls_mpi_cmp_mpi(&mpi, &read));
        }
#endif /* MBEDTLS_ASN1_PARSE_C */
        /* Skip some intermediate lengths, they're boring. */
        if (expected->len > 10 && data.size == 8) {
            data.size = expected->len - 2;
        }
    }

exit:
    mbedtls_mpi_free(&mpi);
    mbedtls_mpi_free(&read);
    mbedtls_free(data.output);
}
/* END_CASE */

/* BEGIN_CASE */
void mbedtls_asn1_write_string(int tag, data_t *content, data_t *expected)
{
    generic_write_data_t data = { NULL, NULL, NULL, NULL, 0 };
    int ret;

    for (data.size = 0; data.size <= expected->len + 1; data.size++) {
        if (!generic_write_start_step(&data)) {
            goto exit;
        }
        switch (tag) {
            case MBEDTLS_ASN1_OCTET_STRING:
                ret = mbedtls_asn1_write_octet_string(
                    &data.p, data.start, content->x, content->len);
                break;
            case MBEDTLS_ASN1_OID:
                ret = mbedtls_asn1_write_oid(
                    &data.p, data.start,
                    (const char *) content->x, content->len);
                break;
            case MBEDTLS_ASN1_UTF8_STRING:
                ret = mbedtls_asn1_write_utf8_string(
                    &data.p, data.start,
```

