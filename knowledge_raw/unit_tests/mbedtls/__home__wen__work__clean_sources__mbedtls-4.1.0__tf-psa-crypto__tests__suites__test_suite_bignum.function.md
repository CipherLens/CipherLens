# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_bignum.function
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
#if defined(MBEDTLS_GENPRIME)
typedef struct mbedtls_test_mpi_random {
    data_t *data;
    size_t  pos;
    size_t  chunk_len;
} mbedtls_test_mpi_random;

/*
 * This function is called by the Miller-Rabin primality test each time it
 * chooses a random witness. The witnesses (or non-witnesses as provided by the
 * test) are stored in the data member of the state structure. Each number is in
 * the format that mbedtls_mpi_read_string understands and is chunk_len long.
 */
static int mbedtls_test_mpi_miller_rabin_determinizer(void *state,
                                                      unsigned char *buf,
                                                      size_t len)
{
    mbedtls_test_mpi_random *random = (mbedtls_test_mpi_random *) state;

    if (random == NULL || random->data->x == NULL || buf == NULL) {
        return -1;
    }

    if (random->pos + random->chunk_len > random->data->len
        || random->chunk_len > len) {
        return -1;
    }

    memset(buf, 0, len);

    /* The witness is written to the end of the buffer, since the buffer is
     * used as big endian, unsigned binary data in mbedtls_mpi_read_binary.
     * Writing the witness to the start of the buffer would result in the
     * buffer being 'witness 000...000', which would be treated as
     * witness * 2^n for some n. */
    memcpy(buf + len - random->chunk_len, &random->data->x[random->pos],
           random->chunk_len);

    random->pos += random->chunk_len;
```

## Call pattern 2

```c
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_BIGNUM_C
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void mpi_null()
{
    mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_mpi_get_bit(&X, 42) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_size(&X) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
```

## Call pattern 3

```c
/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_BIGNUM_C
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void mpi_null()
{
    mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_mpi_get_bit(&X, 42) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_size(&X) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
```

## Call pattern 4

```c
/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_BIGNUM_C
 * END_DEPENDENCIES
 */

/* BEGIN_CASE */
void mpi_null()
{
    mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_mpi_get_bit(&X, 42) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_size(&X) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
```

## Call pattern 5

```c
mbedtls_mpi X, Y, Z;

    mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&Z);

    TEST_ASSERT(mbedtls_mpi_get_bit(&X, 42) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == 0);
    TEST_ASSERT(mbedtls_mpi_size(&X) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_write_string(&X, radix_A, str, output_size, &len) == result_write);
        if (result_write == 0) {
            TEST_ASSERT(strcmp(str, input_A) == 0);
            TEST_ASSERT(str[len] == '!');
        }
    }

exit:
```

## Call pattern 6

```c
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_write_string(&X, radix_A, str, output_size, &len) == result_write);
        if (result_write == 0) {
            TEST_ASSERT(strcmp(str, input_A) == 0);
            TEST_ASSERT(str[len] == '!');
        }
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
```

## Call pattern 7

```c
void mpi_read_write_string(int radix_X, char *input_X, int radix_A,
                           char *input_A, int output_size, int result_read,
                           int result_write)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_write_string(&X, radix_A, str, output_size, &len) == result_write);
        if (result_write == 0) {
            TEST_ASSERT(strcmp(str, input_A) == 0);
            TEST_ASSERT(str[len] == '!');
        }
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
```

## Call pattern 8

```c
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);

    memset(str, '!', sizeof(str));

    TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_write_string(&X, radix_A, str, output_size, &len) == result_write);
        if (result_write == 0) {
            TEST_ASSERT(strcmp(str, input_A) == 0);
            TEST_ASSERT(str[len] == '!');
        }
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
```

## Call pattern 9

```c
TEST_ASSERT(mbedtls_mpi_read_string(&X, radix_X, input_X) == result_read);
    if (result_read == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_write_string(&X, radix_A, str, output_size, &len) == result_write);
        if (result_write == 0) {
            TEST_ASSERT(strcmp(str, input_A) == 0);
            TEST_ASSERT(str[len] == '!');
        }
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
```

## Call pattern 10

```c
exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);
```

## Call pattern 11

```c
/* BEGIN_CASE */
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */
```

## Call pattern 12

```c
void mpi_zero_length_buffer_is_null()
{
    mbedtls_mpi X;
    size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
```

## Call pattern 13

```c
size_t olen;

    mbedtls_mpi_init(&X);

    /* Simply test that the following functions do not crash when a NULL buffer
     * pointer and 0 length is passed. We don't care much about the return value. */
    TEST_EQUAL(mbedtls_mpi_read_binary(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_read_binary_le(&X, NULL, 0), 0);
    TEST_EQUAL(mbedtls_mpi_write_string(&X, 16, NULL, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
    TEST_EQUAL(mbedtls_mpi_write_binary(&X, NULL, 0), 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
```

## Call pattern 14

```c
exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);
```

## Call pattern 15

```c
/* BEGIN_CASE */
void mpi_read_binary(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */
```

## Call pattern 16

```c
char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
```

## Call pattern 17

```c
exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
```

## Call pattern 18

```c
/* BEGIN_CASE */
void mpi_read_binary_le(data_t *buf, char *input_A)
{
    mbedtls_mpi X;
    char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
```

## Call pattern 19

```c
char str[1000];
    size_t len;

    mbedtls_mpi_init(&X);


    TEST_ASSERT(mbedtls_mpi_read_binary_le(&X, buf->x, buf->len) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_write_string(&X, 16, str, sizeof(str), &len) == 0);
    TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */
```

## Call pattern 20

```c
TEST_ASSERT(strcmp((char *) str, input_A) == 0);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary_le(char *input_X, data_t *input_A,
                         int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;
```

## Call pattern 21

```c
/* BEGIN_CASE */
void mpi_write_binary(char *input_X, data_t *input_A,
                      int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary_le(char *input_X, data_t *input_A,
                         int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary_le(&X, buf, output_size), result);

    if (result == 0) {
```

## Call pattern 22

```c
TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary_le(char *input_X, data_t *input_A,
                         int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary_le(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */
```

## Call pattern 23

```c
exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_write_binary_le(char *input_X, data_t *input_A,
                         int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary_le(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_read_file(char *input_file, data_t *input_A, int result)
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;
```

## Call pattern 24

```c
/* BEGIN_CASE */
void mpi_write_binary_le(char *input_X, data_t *input_A,
                         int output_size, int result)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    unsigned char *buf = NULL;

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);

    TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary_le(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_read_file(char *input_file, data_t *input_A, int result)
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;

    memset(buf, 0x00, 1000);

    mbedtls_mpi_init(&X);

    file = fopen(input_file, "r");
    TEST_ASSERT(file != NULL);
```

## Call pattern 25

```c
TEST_CALLOC(buf, output_size);

    TEST_EQUAL(mbedtls_mpi_write_binary_le(&X, buf, output_size), result);

    if (result == 0) {
        TEST_EQUAL(mbedtls_test_hexcmp(buf, input_A->x,
                                       output_size, input_A->len), 0);
    }

exit:
    mbedtls_free(buf);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_read_file(char *input_file, data_t *input_A, int result)
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;

    memset(buf, 0x00, 1000);

    mbedtls_mpi_init(&X);

    file = fopen(input_file, "r");
    TEST_ASSERT(file != NULL);
    ret = mbedtls_mpi_read_file(&X, 16, file);
    fclose(file);
    TEST_ASSERT(ret == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        buflen = mbedtls_mpi_size(&X);
        TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, buflen) == 0);
```

## Call pattern 26

```c
/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_read_file(char *input_file, data_t *input_A, int result)
{
    mbedtls_mpi X;
    unsigned char buf[1000];
    size_t buflen;
    FILE *file;
    int ret;

    memset(buf, 0x00, 1000);

    mbedtls_mpi_init(&X);

    file = fopen(input_file, "r");
    TEST_ASSERT(file != NULL);
    ret = mbedtls_mpi_read_file(&X, 16, file);
    fclose(file);
    TEST_ASSERT(ret == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        buflen = mbedtls_mpi_size(&X);
        TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, buflen) == 0);


        TEST_ASSERT(mbedtls_test_hexcmp(buf, input_A->x,
                                        buflen, input_A->len) == 0);
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_write_file(char *input_X, char *output_file)
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
```

## Call pattern 27

```c
mbedtls_mpi_init(&X);

    file = fopen(input_file, "r");
    TEST_ASSERT(file != NULL);
    ret = mbedtls_mpi_read_file(&X, 16, file);
    fclose(file);
    TEST_ASSERT(ret == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        buflen = mbedtls_mpi_size(&X);
        TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, buflen) == 0);


        TEST_ASSERT(mbedtls_test_hexcmp(buf, input_A->x,
                                        buflen, input_A->len) == 0);
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_write_file(char *input_X, char *output_file)
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
    int ret;

    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    file_out = fopen(output_file, "w");
    TEST_ASSERT(file_out != NULL);
    ret = mbedtls_mpi_write_file(NULL, &X, 16, file_out);
    fclose(file_out);
    TEST_ASSERT(ret == 0);
```

## Call pattern 28

```c
if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        buflen = mbedtls_mpi_size(&X);
        TEST_ASSERT(mbedtls_mpi_write_binary(&X, buf, buflen) == 0);


        TEST_ASSERT(mbedtls_test_hexcmp(buf, input_A->x,
                                        buflen, input_A->len) == 0);
    }

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_write_file(char *input_X, char *output_file)
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
    int ret;

    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    file_out = fopen(output_file, "w");
    TEST_ASSERT(file_out != NULL);
    ret = mbedtls_mpi_write_file(NULL, &X, 16, file_out);
    fclose(file_out);
    TEST_ASSERT(ret == 0);

    file_in = fopen(output_file, "r");
    TEST_ASSERT(file_in != NULL);
    ret = mbedtls_mpi_read_file(&Y, 16, file_in);
    fclose(file_in);
    TEST_ASSERT(ret == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
```

## Call pattern 29

```c
exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_FS_IO */
void mpi_write_file(char *input_X, char *output_file)
{
    mbedtls_mpi X, Y;
    FILE *file_out, *file_in;
    int ret;

    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    file_out = fopen(output_file, "w");
    TEST_ASSERT(file_out != NULL);
    ret = mbedtls_mpi_write_file(NULL, &X, 16, file_out);
    fclose(file_out);
    TEST_ASSERT(ret == 0);

    file_in = fopen(output_file, "r");
    TEST_ASSERT(file_in != NULL);
    ret = mbedtls_mpi_read_file(&Y, 16, file_in);
    fclose(file_in);
    TEST_ASSERT(ret == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_get_bit(char *input_X, int pos, int val)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
```

## Call pattern 30

```c
fclose(file_out);
    TEST_ASSERT(ret == 0);

    file_in = fopen(output_file, "r");
    TEST_ASSERT(file_in != NULL);
    ret = mbedtls_mpi_read_file(&Y, 16, file_in);
    fclose(file_in);
    TEST_ASSERT(ret == 0);

    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_get_bit(char *input_X, int pos, int val)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_get_bit(&X, pos) == val);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_set_bit(char *input_X, int pos, int val,
                 char *output_Y, int result)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, output_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_set_bit(&X, pos, val) == result);
```

## Call pattern 31

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_get_bit(char *input_X, int pos, int val)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_get_bit(&X, pos) == val);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_set_bit(char *input_X, int pos, int val,
                 char *output_Y, int result)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, output_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_set_bit(&X, pos, val) == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
```

## Call pattern 32

```c
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_get_bit(char *input_X, int pos, int val)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_get_bit(&X, pos) == val);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_set_bit(char *input_X, int pos, int val,
                 char *output_Y, int result)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, output_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_set_bit(&X, pos, val) == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lsb(char *input_X, int nr_bits)
{
```

## Call pattern 33

```c
TEST_ASSERT(mbedtls_mpi_get_bit(&X, pos) == val);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_set_bit(char *input_X, int pos, int val,
                 char *output_Y, int result)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, output_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_set_bit(&X, pos, val) == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lsb(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
```

## Call pattern 34

```c
mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, output_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_set_bit(&X, pos, val) == result);

    if (result == 0) {
        TEST_ASSERT(sign_is_valid(&X));
        TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lsb(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_bitlen(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
```

## Call pattern 35

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == 0);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lsb(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_bitlen(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_gcd(char *input_X, char *input_Y,
             char *input_A)
{
```

## Call pattern 36

```c
/* END_CASE */

/* BEGIN_CASE */
void mpi_lsb(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_bitlen(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_gcd(char *input_X, char *input_Y,
             char *input_A)
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init(&A); mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&Y, input_Y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&A, input_A), 0);
```

## Call pattern 37

```c
TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_lsb(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_bitlen(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_gcd(char *input_X, char *input_Y,
             char *input_A)
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init(&A); mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&Y, input_Y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&A, input_A), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &X. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_X), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, /* X */ &Z, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
```

## Call pattern 38

```c
/* END_CASE */

/* BEGIN_CASE */
void mpi_bitlen(char *input_X, int nr_bits)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_gcd(char *input_X, char *input_Y,
             char *input_A)
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init(&A); mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&Y, input_Y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&A, input_A), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &X. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_X), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, /* X */ &Z, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &Y. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_Y), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, /* Y */ &Z), 0);
    TEST_ASSERT(sign_is_valid(&Z));
```

## Call pattern 39

```c
TEST_ASSERT(mbedtls_mpi_bitlen(&X) == (size_t) nr_bits);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_gcd(char *input_X, char *input_Y,
             char *input_A)
{
    mbedtls_mpi A, X, Y, Z;
    mbedtls_mpi_init(&A); mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);

    TEST_EQUAL(mbedtls_test_read_mpi(&X, input_X), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&Y, input_Y), 0);
    TEST_EQUAL(mbedtls_test_read_mpi(&A, input_A), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &X. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_X), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, /* X */ &Z, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &Y. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_Y), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, /* Y */ &Z), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

exit:
    mbedtls_mpi_free(&A); mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_int(int input_X, int input_A, int result_CMP)
```

## Call pattern 40

```c
TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_X), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, /* X */ &Z, &Y), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

    /* Test pointer aliasing where &Z == &Y. */
    TEST_EQUAL(mbedtls_test_read_mpi(&Z, input_Y), 0);
    TEST_EQUAL(mbedtls_mpi_gcd(&Z, &X, /* Y */ &Z), 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

exit:
    mbedtls_mpi_free(&A); mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_int(int input_X, int input_A, int result_CMP)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_lset(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, input_A) == result_CMP);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);
```

## Call pattern 41

```c
TEST_ASSERT(sign_is_valid(&Z));
    TEST_EQUAL(mbedtls_mpi_cmp_mpi(&Z, &A), 0);

exit:
    mbedtls_mpi_free(&A); mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_int(int input_X, int input_A, int result_CMP)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_lset(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, input_A) == result_CMP);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
```

## Call pattern 42

```c
exit:
    mbedtls_mpi_free(&A); mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_int(int input_X, int input_A, int result_CMP)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_lset(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, input_A) == result_CMP);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
                   int size_Y, char *input_Y,
                   int input_ret, int input_err)
```

## Call pattern 43

```c
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_int(int input_X, int input_A, int result_CMP)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_lset(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, input_A) == result_CMP);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
                   int size_Y, char *input_Y,
                   int input_ret, int input_err)
{
    unsigned ret = -1;
    unsigned input_uret = input_ret;
    mbedtls_mpi X, Y;
```

## Call pattern 44

```c
TEST_ASSERT(mbedtls_mpi_cmp_int(&X, input_A) == result_CMP);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
                   int size_Y, char *input_Y,
                   int input_ret, int input_err)
{
    unsigned ret = -1;
    unsigned input_uret = input_ret;
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_grow(&X, size_X) == 0);
    TEST_ASSERT(mbedtls_mpi_grow(&Y, size_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_lt_mpi_ct(&X, &Y, &ret) == input_err);
```

## Call pattern 45

```c
/* BEGIN_CASE */
void mpi_cmp_mpi(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
                   int size_Y, char *input_Y,
                   int input_ret, int input_err)
{
    unsigned ret = -1;
    unsigned input_uret = input_ret;
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_grow(&X, size_X) == 0);
    TEST_ASSERT(mbedtls_mpi_grow(&Y, size_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_lt_mpi_ct(&X, &Y, &ret) == input_err);
    if (input_err == 0) {
        TEST_EQUAL(ret, input_uret);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
```

## Call pattern 46

```c
mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_lt_mpi_ct(int size_X, char *input_X,
                   int size_Y, char *input_Y,
                   int input_ret, int input_err)
{
    unsigned ret = -1;
    unsigned input_uret = input_ret;
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_grow(&X, size_X) == 0);
    TEST_ASSERT(mbedtls_mpi_grow(&Y, size_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_lt_mpi_ct(&X, &Y, &ret) == input_err);
    if (input_err == 0) {
        TEST_EQUAL(ret, input_uret);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_abs(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);
```

## Call pattern 47

```c
TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_grow(&X, size_X) == 0);
    TEST_ASSERT(mbedtls_mpi_grow(&Y, size_Y) == 0);

    TEST_ASSERT(mbedtls_mpi_lt_mpi_ct(&X, &Y, &ret) == input_err);
    if (input_err == 0) {
        TEST_EQUAL(ret, input_uret);
    }

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_abs(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);
```

## Call pattern 48

```c
}

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_cmp_abs(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);
```

## Call pattern 49

```c
/* BEGIN_CASE */
void mpi_cmp_abs(char *input_X, char *input_Y,
                 int input_A)
{
    mbedtls_mpi X, Y;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);
```

## Call pattern 50

```c
TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
```

## Call pattern 51

```c
TEST_ASSERT(mbedtls_mpi_cmp_abs(&X, &Y) == input_A);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
```

## Call pattern 52

```c
exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy(char *src_hex, char *dst_hex)
{
    mbedtls_mpi src, dst, ref;
    mbedtls_mpi_init(&src);
    mbedtls_mpi_init(&dst);
    mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
```

## Call pattern 53

```c
mbedtls_mpi_init(&ref);

    TEST_ASSERT(mbedtls_test_read_mpi(&src, src_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&ref, dst_hex) == 0);

    /* mbedtls_mpi_copy() */
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
```

## Call pattern 54

```c
TEST_ASSERT(mbedtls_mpi_copy(&dst, &src) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
```

## Call pattern 55

```c
TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 1) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
```

## Call pattern 56

```c
TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
```

## Call pattern 57

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &src) == 0);

    /* mbedtls_mpi_safe_cond_assign(), assignment not done */
    mbedtls_mpi_free(&dst);
    TEST_ASSERT(mbedtls_test_read_mpi(&dst, dst_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_assign(&dst, &src, 0) == 0);
    TEST_ASSERT(sign_is_valid(&dst));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&dst, &ref) == 0);

exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
```

## Call pattern 58

```c
exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
```

## Call pattern 59

```c
exit:
    mbedtls_mpi_free(&src);
    mbedtls_mpi_free(&dst);
    mbedtls_mpi_free(&ref);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_copy_self(char *input_X)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
```

## Call pattern 60

```c
mbedtls_mpi X, A;
    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
```

## Call pattern 61

```c
mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_copy(&X, &X) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
```

## Call pattern 62

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
```

## Call pattern 63

```c
exit:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap(char *X_hex, char *Y_hex)
{
    mbedtls_mpi X, Y, X0, Y0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y);
    mbedtls_mpi_init(&X0); mbedtls_mpi_init(&Y0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
```

## Call pattern 64

```c
TEST_ASSERT(mbedtls_test_read_mpi(&Y0, Y_hex) == 0);

    /* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
```

## Call pattern 65

```c
/* mbedtls_mpi_swap() */
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    mbedtls_mpi_swap(&X, &Y);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
```

## Call pattern 66

```c
/* mbedtls_mpi_safe_cond_swap(), swap done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
```

## Call pattern 67

```c
mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 1) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &Y0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &X0) == 0);

    /* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
```

## Call pattern 68

```c
/* mbedtls_mpi_safe_cond_swap(), swap not done */
    mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&X0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_shrink(int before, int used, int min, int after)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
```

## Call pattern 69

```c
mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, Y_hex) == 0);
    TEST_ASSERT(mbedtls_mpi_safe_cond_swap(&X, &Y, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&X0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_shrink(int before, int used, int min, int after)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);
```

## Call pattern 70

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &Y0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y);
    mbedtls_mpi_free(&X0); mbedtls_mpi_free(&Y0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_swap_self(char *X_hex)
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&X0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_shrink(int before, int used, int min, int after)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_grow(&X, before) == 0);
    if (used > 0) {
        size_t used_bit_count = used * 8 * sizeof(mbedtls_mpi_uint);
        TEST_ASSERT(mbedtls_mpi_set_bit(&X, used_bit_count - 1, 1) == 0);
    }
    TEST_EQUAL(X.n, (size_t) before);
    TEST_ASSERT(mbedtls_mpi_shrink(&X, min) == 0);
    TEST_EQUAL(X.n, (size_t) after);
```

## Call pattern 71

```c
{
    mbedtls_mpi X, X0;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&X0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, X_hex) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X0, X_hex) == 0);

    mbedtls_mpi_swap(&X, &X);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&X0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_shrink(int before, int used, int min, int after)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_grow(&X, before) == 0);
    if (used > 0) {
        size_t used_bit_count = used * 8 * sizeof(mbedtls_mpi_uint);
        TEST_ASSERT(mbedtls_mpi_set_bit(&X, used_bit_count - 1, 1) == 0);
    }
    TEST_EQUAL(X.n, (size_t) before);
    TEST_ASSERT(mbedtls_mpi_shrink(&X, min) == 0);
    TEST_EQUAL(X.n, (size_t) after);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
```

## Call pattern 72

```c
TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &X0) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&X0);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_shrink(int before, int used, int min, int after)
{
    mbedtls_mpi X;
    mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_grow(&X, before) == 0);
    if (used > 0) {
        size_t used_bit_count = used * 8 * sizeof(mbedtls_mpi_uint);
        TEST_ASSERT(mbedtls_mpi_set_bit(&X, used_bit_count - 1, 1) == 0);
    }
    TEST_EQUAL(X.n, (size_t) before);
    TEST_ASSERT(mbedtls_mpi_shrink(&X, min) == 0);
    TEST_EQUAL(X.n, (size_t) after);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
```

## Call pattern 73

```c
mbedtls_mpi_init(&X);

    TEST_ASSERT(mbedtls_mpi_grow(&X, before) == 0);
    if (used > 0) {
        size_t used_bit_count = used * 8 * sizeof(mbedtls_mpi_uint);
        TEST_ASSERT(mbedtls_mpi_set_bit(&X, used_bit_count - 1, 1) == 0);
    }
    TEST_EQUAL(X.n, (size_t) before);
    TEST_ASSERT(mbedtls_mpi_shrink(&X, min) == 0);
    TEST_EQUAL(X.n, (size_t) after);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

    /* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);
```

## Call pattern 74

```c
TEST_EQUAL(X.n, (size_t) after);

exit:
    mbedtls_mpi_free(&X);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

    /* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi_inplace(char *input_X, char *input_A)
{
```

## Call pattern 75

```c
/* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_mpi(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi_inplace(char *input_X, char *input_A)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_sub_abs(&X, &X, &X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
```

## Call pattern 76

```c
TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_mpi_inplace(char *input_X, char *input_A)
{
    mbedtls_mpi X, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_sub_abs(&X, &X, &X) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&X, 0) == 0);
    TEST_ASSERT(sign_is_valid(&X));

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&A);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_add_abs(char *input_X, char *input_Y,
                 char *input_A)
```

## Call pattern 77

```c
TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_mpi_add_mpi(&X, &X, &X) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&A);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_add_abs(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_abs(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

    /* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
```

## Call pattern 78

```c
exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&A);
}
/* END_CASE */


/* BEGIN_CASE */
void mpi_add_abs(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_abs(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

    /* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_int(char *input_X, int input_Y,
                 char *input_A)
```

## Call pattern 79

```c
/* result == first operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&X, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&X));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&X, &A) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);

    /* result == second operand */
    TEST_ASSERT(mbedtls_mpi_add_abs(&Y, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Y));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_int(char *input_X, int input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_int(&Z, &X, input_Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_sub_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);
```

## Call pattern 80

```c
TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Y, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_add_int(char *input_X, int input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_add_int(&Z, &X, input_Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

exit:
    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Z); mbedtls_mpi_free(&A);
}
/* END_CASE */

/* BEGIN_CASE */
void mpi_sub_mpi(char *input_X, char *input_Y,
                 char *input_A)
{
    mbedtls_mpi X, Y, Z, A;
    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z); mbedtls_mpi_init(&A);

    TEST_ASSERT(mbedtls_test_read_mpi(&X, input_X) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&Y, input_Y) == 0);
    TEST_ASSERT(mbedtls_test_read_mpi(&A, input_A) == 0);
    TEST_ASSERT(mbedtls_mpi_sub_mpi(&Z, &X, &Y) == 0);
    TEST_ASSERT(sign_is_valid(&Z));
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&Z, &A) == 0);

    /* result == first operand */
```

