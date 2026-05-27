# Official API knowledge snippets: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/drivers/builtin/src/bignum.c
Knowledge type: api_constraints

## Snippet 1

```c
cleanup:
    return ret;
}

/* Implementation that should never be optimized out by the compiler */
#define mbedtls_mpi_zeroize_and_free(v, n) mbedtls_zeroize_and_free(v, ciL * (n))

/*
 * Initialize one MPI
 */
void mbedtls_mpi_init(mbedtls_mpi *X)
{
    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void mbedtls_mpi_free(mbedtls_mpi *X)
{
    if (X == NULL) {
        return;
    }

    if (X->p != NULL) {
        mbedtls_mpi_zeroize_and_free(X->p, X->n);
```

## Snippet 2

```c
void mbedtls_mpi_init(mbedtls_mpi *X)
{
    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Unallocate one MPI
 */
void mbedtls_mpi_free(mbedtls_mpi *X)
{
    if (X == NULL) {
        return;
    }

    if (X->p != NULL) {
        mbedtls_mpi_zeroize_and_free(X->p, X->n);
    }

    X->s = 1;
    X->n = 0;
    X->p = NULL;
}

/*
 * Enlarge to the specified number of limbs
 */
```

## Snippet 3

```c
X->n = (unsigned short) i;
    X->p = p;

    return 0;
}

/* Resize X to have exactly n limbs and set it to 0. */
static int mbedtls_mpi_resize_clear(mbedtls_mpi *X, size_t limbs)
{
    if (limbs == 0) {
        mbedtls_mpi_free(X);
        return 0;
    } else if (X->n == limbs) {
        memset(X->p, 0, limbs * ciL);
        X->s = 1;
        return 0;
    } else {
        mbedtls_mpi_free(X);
        return mbedtls_mpi_grow(X, limbs);
    }
}

/*
 * Copy the contents of Y into X.
 *
 * This function is not constant-time. Leading zeros in Y may be removed.
 *
 * Ensure that X does not shrink. This is not guaranteed by the public API,
```

## Snippet 4

```c
static int mbedtls_mpi_resize_clear(mbedtls_mpi *X, size_t limbs)
{
    if (limbs == 0) {
        mbedtls_mpi_free(X);
        return 0;
    } else if (X->n == limbs) {
        memset(X->p, 0, limbs * ciL);
        X->s = 1;
        return 0;
    } else {
        mbedtls_mpi_free(X);
        return mbedtls_mpi_grow(X, limbs);
    }
}

/*
 * Copy the contents of Y into X.
 *
 * This function is not constant-time. Leading zeros in Y may be removed.
 *
 * Ensure that X does not shrink. This is not guaranteed by the public API,
 * but some code in the bignum module might still rely on this property.
 */
int mbedtls_mpi_copy(mbedtls_mpi *X, const mbedtls_mpi *Y)
{
    int ret = 0;
    size_t i;
```

## Snippet 5

```c
return (mbedtls_mpi_uint) 0 - (mbedtls_mpi_uint) z;
}

/* Convert x to a sign, i.e. to 1, if x is positive, or -1, if x is negative.
 * This looks awkward but generates smaller code than (x < 0 ? -1 : 1) */
#define TO_SIGN(x) ((mbedtls_mpi_sint) (((mbedtls_mpi_uint) x) >> (biL - 1)) * -2 + 1)

/*
 * Set value from integer
 */
int mbedtls_mpi_lset(mbedtls_mpi *X, mbedtls_mpi_sint z)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, 1));
    memset(X->p, 0, X->n * ciL);

    X->p[0] = mpi_sint_abs(z);
    X->s    = TO_SIGN(z);

cleanup:

    return ret;
}

/*
 * Get a specific bit
 */
```

## Snippet 6

```c
if (*d >= (mbedtls_mpi_uint) radix) {
        return MBEDTLS_ERR_MPI_INVALID_CHARACTER;
    }

    return 0;
}

/*
 * Import from an ASCII string
 */
int mbedtls_mpi_read_string(mbedtls_mpi *X, int radix, const char *s)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j, slen, n;
    int sign = 1;
    mbedtls_mpi_uint d;
    mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&T);

    if (s[0] == 0) {
        mbedtls_mpi_free(X);
        return 0;
    }
```

## Snippet 7

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j, slen, n;
    int sign = 1;
    mbedtls_mpi_uint d;
    mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&T);

    if (s[0] == 0) {
        mbedtls_mpi_free(X);
        return 0;
    }

    if (s[0] == '-') {
        ++s;
        sign = -1;
    }

    slen = strlen(s);

    if (radix == 16) {
        if (slen > SIZE_MAX >> 2) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }
```

## Snippet 8

```c
mbedtls_mpi_uint d;
    mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&T);

    if (s[0] == 0) {
        mbedtls_mpi_free(X);
        return 0;
    }

    if (s[0] == '-') {
        ++s;
        sign = -1;
    }

    slen = strlen(s);

    if (radix == 16) {
        if (slen > SIZE_MAX >> 2) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        n = BITS_TO_LIMBS(slen << 2);
```

## Snippet 9

```c
slen = strlen(s);

    if (radix == 16) {
        if (slen > SIZE_MAX >> 2) {
            return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        }

        n = BITS_TO_LIMBS(slen << 2);

        MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, n));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 0));

        for (i = slen, j = 0; i > 0; i--, j++) {
            MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i - 1]));
            X->p[j / (2 * ciL)] |= d << ((j % (2 * ciL)) << 2);
        }
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 0));

        for (i = 0; i < slen; i++) {
            MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i]));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&T, X, radix));
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(X, &T, d));
        }
    }

    if (sign < 0 && mbedtls_mpi_bitlen(X) != 0) {
        X->s = -1;
```

## Snippet 10

```c
n = BITS_TO_LIMBS(slen << 2);

        MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, n));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 0));

        for (i = slen, j = 0; i > 0; i--, j++) {
            MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i - 1]));
            X->p[j / (2 * ciL)] |= d << ((j % (2 * ciL)) << 2);
        }
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 0));

        for (i = 0; i < slen; i++) {
            MBEDTLS_MPI_CHK(mpi_get_digit(&d, radix, s[i]));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&T, X, radix));
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(X, &T, d));
        }
    }

    if (sign < 0 && mbedtls_mpi_bitlen(X) != 0) {
        X->s = -1;
    }

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
```

## Snippet 11

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(X, &T, d));
        }
    }

    if (sign < 0 && mbedtls_mpi_bitlen(X) != 0) {
        X->s = -1;
    }

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
}

/*
 * Helper to write the digits high-order first.
 */
static int mpi_write_hlp(mbedtls_mpi *X, int radix,
                         char **p, const size_t buflen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_uint r;
    size_t length = 0;
    char *p_end = *p + buflen;

    do {
        if (length >= buflen) {
```

## Snippet 12

```c
*p += length;

cleanup:

    return ret;
}

/*
 * Export into an ASCII string
 */
int mbedtls_mpi_write_string(const mbedtls_mpi *X, int radix,
                             char *buf, size_t buflen, size_t *olen)
{
    int ret = 0;
    size_t n;
    char *p;
    mbedtls_mpi T;

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    n = mbedtls_mpi_bitlen(X);   /* Number of bits necessary to present `n`. */
    if (radix >=  4) {
        n >>= 1;                 /* Number of 4-adic digits necessary to present
                                  * `n`. If radix > 4, this might be a strict
                                  * overapproximation of the number of
                                  * radix-adic digits needed to present `n`. */
```

## Snippet 13

```c
n += 1; /* Potential '-'-sign. */
    n += (n & 1);   /* Make n even to have enough space for hexadecimal writing,
                     * which always uses an even number of hex-digits. */

    if (buflen < n) {
        *olen = n;
        return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
    }

    p = buf;
    mbedtls_mpi_init(&T);

    if (X->s == -1) {
        *p++ = '-';
        buflen--;
    }

    if (radix == 16) {
        int c;
        size_t i, j, k;

        for (i = X->n, k = 0; i > 0; i--) {
            for (j = ciL; j > 0; j--) {
                c = (X->p[i - 1] >> ((j - 1) << 3)) & 0xFF;

                if (c == 0 && k == 0 && (i + j) != 2) {
                    continue;
                }
```

## Snippet 14

```c
}

        MBEDTLS_MPI_CHK(mpi_write_hlp(&T, radix, &p, buflen));
    }

    *p++ = '\0';
    *olen = (size_t) (p - buf);

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
}

#if defined(MBEDTLS_FS_IO)
/*
 * Read X from an opened file
 */
int mbedtls_mpi_read_file(mbedtls_mpi *X, int radix, FILE *fin)
{
    mbedtls_mpi_uint d;
    size_t slen;
    char *p;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
```

## Snippet 15

```c
slen--; s[slen] = '\0';
    }

    p = s + slen;
    while (p-- > s) {
        if (mpi_get_digit(&d, radix, *p) != 0) {
            break;
        }
    }

    return mbedtls_mpi_read_string(X, radix, p + 1);
}

/*
 * Write X into an opened file (or stdout if fout == NULL)
 */
int mbedtls_mpi_write_file(const char *p, const mbedtls_mpi *X, int radix, FILE *fout)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n, slen, plen;
    /*
     * Buffer should have space for (short) label and decimal formatted MPI,
     * newline characters and '\0'
     */
    char s[MBEDTLS_MPI_RW_BUFFER_SIZE];

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
```

## Snippet 16

```c
* newline characters and '\0'
     */
    char s[MBEDTLS_MPI_RW_BUFFER_SIZE];

    if (radix < 2 || radix > 16) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    memset(s, 0, sizeof(s));

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_string(X, radix, s, sizeof(s) - 2, &n));

    if (p == NULL) {
        p = "";
    }

    plen = strlen(p);
    slen = strlen(s);
    s[slen++] = '\r';
    s[slen++] = '\n';

    if (fout != NULL) {
        if (fwrite(p, 1, plen, fout) != plen ||
            fwrite(s, 1, slen, fout) != slen) {
            return MBEDTLS_ERR_MPI_FILE_IO_ERROR;
        }
    } else {
        mbedtls_printf("%s%s", p, s);
```

## Snippet 17

```c
* This function is also used to import keys. However, wiping the buffers
     * upon failure is not necessary because failure only can happen before any
     * input is copied.
     */
    return ret;
}

/*
 * Export X into unsigned binary data, little endian
 */
int mbedtls_mpi_write_binary_le(const mbedtls_mpi *X,
                                unsigned char *buf, size_t buflen)
{
    return mbedtls_mpi_core_write_le(X->p, X->n, buf, buflen);
}

/*
 * Export X into unsigned binary data, big endian
 */
int mbedtls_mpi_write_binary(const mbedtls_mpi *X,
                             unsigned char *buf, size_t buflen)
{
    return mbedtls_mpi_core_write_be(X->p, X->n, buf, buflen);
}

/*
 * Left-shift: X <<= count
 */
```

## Snippet 18

```c
*/
int mbedtls_mpi_write_binary_le(const mbedtls_mpi *X,
                                unsigned char *buf, size_t buflen)
{
    return mbedtls_mpi_core_write_le(X->p, X->n, buf, buflen);
}

/*
 * Export X into unsigned binary data, big endian
 */
int mbedtls_mpi_write_binary(const mbedtls_mpi *X,
                             unsigned char *buf, size_t buflen)
{
    return mbedtls_mpi_core_write_be(X->p, X->n, buf, buflen);
}

/*
 * Left-shift: X <<= count
 */
int mbedtls_mpi_shift_l(mbedtls_mpi *X, size_t count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;

    i = mbedtls_mpi_bitlen(X) + count;

    if (X->n * biL < i) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, BITS_TO_LIMBS(i)));
```

## Snippet 19

```c
/*
 * Baseline multiplication: X = A * B  (HAC 14.12)
 */
int mbedtls_mpi_mul_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j;
    mbedtls_mpi TA, TB;
    int result_is_zero = 0;

    mbedtls_mpi_init(&TA);
    mbedtls_mpi_init(&TB);

    if (X == A) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TA, A)); A = &TA;
    }
    if (X == B) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TB, B)); B = &TB;
    }

    for (i = A->n; i > 0; i--) {
        if (A->p[i - 1] != 0) {
            break;
        }
    }
    if (i == 0) {
        result_is_zero = 1;
    }
```

## Snippet 20

```c
* Baseline multiplication: X = A * B  (HAC 14.12)
 */
int mbedtls_mpi_mul_mpi(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, j;
    mbedtls_mpi TA, TB;
    int result_is_zero = 0;

    mbedtls_mpi_init(&TA);
    mbedtls_mpi_init(&TB);

    if (X == A) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TA, A)); A = &TA;
    }
    if (X == B) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TB, B)); B = &TB;
    }

    for (i = A->n; i > 0; i--) {
        if (A->p[i - 1] != 0) {
            break;
        }
    }
    if (i == 0) {
        result_is_zero = 1;
    }
```

## Snippet 21

```c
for (j = B->n; j > 0; j--) {
        if (B->p[j - 1] != 0) {
            break;
        }
    }
    if (j == 0) {
        result_is_zero = 1;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, i + j));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 0));

    mbedtls_mpi_core_mul(X->p, A->p, i, B->p, j);

    /* If the result is 0, we don't shortcut the operation, which reduces
     * but does not eliminate side channels leaking the zero-ness. We do
     * need to take care to set the sign bit properly since the library does
     * not fully support an MPI object with a value of 0 and s == -1. */
    if (result_is_zero) {
        X->s = 1;
    } else {
        X->s = A->s * B->s;
    }

cleanup:

    mbedtls_mpi_free(&TB); mbedtls_mpi_free(&TA);
```

## Snippet 22

```c
* need to take care to set the sign bit properly since the library does
     * not fully support an MPI object with a value of 0 and s == -1. */
    if (result_is_zero) {
        X->s = 1;
    } else {
        X->s = A->s * B->s;
    }

cleanup:

    mbedtls_mpi_free(&TB); mbedtls_mpi_free(&TA);

    return ret;
}

/*
 * Baseline multiplication: X = A * b
 */
int mbedtls_mpi_mul_int(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint b)
{
    size_t n = A->n;
    while (n > 0 && A->p[n - 1] == 0) {
        --n;
    }

    /* The general method below doesn't work if b==0. */
    if (b == 0 || n == 0) {
        return mbedtls_mpi_lset(X, 0);
```

## Snippet 23

```c
*/
int mbedtls_mpi_mul_int(mbedtls_mpi *X, const mbedtls_mpi *A, mbedtls_mpi_uint b)
{
    size_t n = A->n;
    while (n > 0 && A->p[n - 1] == 0) {
        --n;
    }

    /* The general method below doesn't work if b==0. */
    if (b == 0 || n == 0) {
        return mbedtls_mpi_lset(X, 0);
    }

    /* Calculate A*b as A + A*(b-1) to take advantage of mbedtls_mpi_core_mla */
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    /* In general, A * b requires 1 limb more than b. If
     * A->p[n - 1] * b / b == A->p[n - 1], then A * b fits in the same
     * number of limbs as A and the call to grow() is not required since
     * copy() will take care of the growth if needed. However, experimentally,
     * making the call to grow() unconditional causes slightly fewer
     * calls to calloc() in ECP code, presumably because it reuses the
     * same mpi for a while and this way the mpi is more likely to directly
     * grow to its final size.
     *
     * Note that calculating A*b as 0 + A*b doesn't work as-is because
     * A,X can be the same. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(X, n + 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, A));
```

## Snippet 24

```c
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, n, t, k;
    mbedtls_mpi X, Y, Z, T1, T2;
    mbedtls_mpi_uint TP2[3];

    if (mbedtls_mpi_cmp_int(B, 0) == 0) {
        return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
    }

    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);
    mbedtls_mpi_init(&T1);
    /*
     * Avoid dynamic memory allocations for constant-size T2.
     *
     * T2 is used for comparison only and the 3 limbs are assigned explicitly,
     * so nobody increase the size of the MPI and we're safe to use an on-stack
     * buffer.
     */
    T2.s = 1;
    T2.n = sizeof(TP2) / sizeof(*TP2);
    T2.p = TP2;

    if (mbedtls_mpi_cmp_abs(A, B) < 0) {
        if (Q != NULL) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(Q, 0));
        }
        if (R != NULL) {
```

## Snippet 25

```c
int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i, n, t, k;
    mbedtls_mpi X, Y, Z, T1, T2;
    mbedtls_mpi_uint TP2[3];

    if (mbedtls_mpi_cmp_int(B, 0) == 0) {
        return MBEDTLS_ERR_MPI_DIVISION_BY_ZERO;
    }

    mbedtls_mpi_init(&X); mbedtls_mpi_init(&Y); mbedtls_mpi_init(&Z);
    mbedtls_mpi_init(&T1);
    /*
     * Avoid dynamic memory allocations for constant-size T2.
     *
     * T2 is used for comparison only and the 3 limbs are assigned explicitly,
     * so nobody increase the size of the MPI and we're safe to use an on-stack
     * buffer.
     */
    T2.s = 1;
    T2.n = sizeof(TP2) / sizeof(*TP2);
    T2.p = TP2;

    if (mbedtls_mpi_cmp_abs(A, B) < 0) {
        if (Q != NULL) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(Q, 0));
        }
        if (R != NULL) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(R, A));
```

## Snippet 26

```c
* T2 is used for comparison only and the 3 limbs are assigned explicitly,
     * so nobody increase the size of the MPI and we're safe to use an on-stack
     * buffer.
     */
    T2.s = 1;
    T2.n = sizeof(TP2) / sizeof(*TP2);
    T2.p = TP2;

    if (mbedtls_mpi_cmp_abs(A, B) < 0) {
        if (Q != NULL) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(Q, 0));
        }
        if (R != NULL) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(R, A));
        }
        return 0;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&X, A));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Y, B));
    X.s = Y.s = 1;

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&Z, A->n + 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&Z,  0));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&T1, A->n + 2));

    k = mbedtls_mpi_bitlen(&Y) % biL;
    if (k < biL - 1) {
```

## Snippet 27

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_copy(R, A));
        }
        return 0;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&X, A));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&Y, B));
    X.s = Y.s = 1;

    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&Z, A->n + 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&Z,  0));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&T1, A->n + 2));

    k = mbedtls_mpi_bitlen(&Y) % biL;
    if (k < biL - 1) {
        k = biL - 1 - k;
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&X, k));
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&Y, k));
    } else {
        k = 0;
    }

    n = X.n - 1;
    t = Y.n - 1;
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&Y, biL * (n - t)));

    while (mbedtls_mpi_cmp_mpi(&X, &Y) >= 0) {
        Z.p[n - t]++;
```

## Snippet 28

```c
}

        T2.p[0] = (i < 2) ? 0 : X.p[i - 2];
        T2.p[1] = (i < 1) ? 0 : X.p[i - 1];
        T2.p[2] = X.p[i];

        Z.p[i - t - 1]++;
        do {
            Z.p[i - t - 1]--;

            MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&T1, 0));
            T1.p[0] = (t < 1) ? 0 : Y.p[t - 1];
            T1.p[1] = Y.p[t];
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&T1, &T1, Z.p[i - t - 1]));
        } while (mbedtls_mpi_cmp_mpi(&T1, &T2) > 0);

        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&T1, &Y, Z.p[i - t - 1]));
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&T1,  biL * (i - t - 1)));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&X, &X, &T1));

        if (mbedtls_mpi_cmp_int(&X, 0) < 0) {
            MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&T1, &Y));
            MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&T1, biL * (i - t - 1)));
            MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&X, &X, &T1));
            Z.p[i - t - 1]--;
        }
    }
```

## Snippet 29

```c
X.s = A->s;
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(R, &X));

        if (mbedtls_mpi_cmp_int(R, 0) == 0) {
            R->s = 1;
        }
    }

cleanup:

    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
    mbedtls_mpi_free(&T1);
    mbedtls_platform_zeroize(TP2, sizeof(TP2));

    return ret;
}

/*
 * Division by int: A = Q * b + R
 */
int mbedtls_mpi_div_int(mbedtls_mpi *Q, mbedtls_mpi *R,
                        const mbedtls_mpi *A,
                        mbedtls_mpi_sint b)
{
    mbedtls_mpi B;
    mbedtls_mpi_uint p[1];

    p[0] = mpi_sint_abs(b);
```

## Snippet 30

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_copy(R, &X));

        if (mbedtls_mpi_cmp_int(R, 0) == 0) {
            R->s = 1;
        }
    }

cleanup:

    mbedtls_mpi_free(&X); mbedtls_mpi_free(&Y); mbedtls_mpi_free(&Z);
    mbedtls_mpi_free(&T1);
    mbedtls_platform_zeroize(TP2, sizeof(TP2));

    return ret;
}

/*
 * Division by int: A = Q * b + R
 */
int mbedtls_mpi_div_int(mbedtls_mpi *Q, mbedtls_mpi *R,
                        const mbedtls_mpi *A,
                        mbedtls_mpi_sint b)
{
    mbedtls_mpi B;
    mbedtls_mpi_uint p[1];

    p[0] = mpi_sint_abs(b);
    B.s = TO_SIGN(b);
```

## Snippet 31

```c
if (mbedtls_mpi_bitlen(E) > MBEDTLS_MPI_MAX_BITS ||
        mbedtls_mpi_bitlen(N) > MBEDTLS_MPI_MAX_BITS) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /*
     * Ensure that the exponent that we are passing to the core is not NULL.
     */
    if (E->n == 0) {
        ret = mbedtls_mpi_lset(X, 1);
        return ret;
    }

    /*
     * Allocate working memory for mbedtls_mpi_core_exp_mod()
     */
    size_t T_limbs = mbedtls_mpi_core_exp_mod_working_limbs(N->n, E->n);
    mbedtls_mpi_uint *T = (mbedtls_mpi_uint *) mbedtls_calloc(T_limbs, sizeof(mbedtls_mpi_uint));
    if (T == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    mbedtls_mpi RR;
    mbedtls_mpi_init(&RR);

    /*
     * If 1st call, pre-compute R^2 mod N
```

## Snippet 32

```c
/*
     * Allocate working memory for mbedtls_mpi_core_exp_mod()
     */
    size_t T_limbs = mbedtls_mpi_core_exp_mod_working_limbs(N->n, E->n);
    mbedtls_mpi_uint *T = (mbedtls_mpi_uint *) mbedtls_calloc(T_limbs, sizeof(mbedtls_mpi_uint));
    if (T == NULL) {
        return MBEDTLS_ERR_MPI_ALLOC_FAILED;
    }

    mbedtls_mpi RR;
    mbedtls_mpi_init(&RR);

    /*
     * If 1st call, pre-compute R^2 mod N
     */
    if (prec_RR == NULL || prec_RR->p == NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_core_get_mont_r2_unsafe(&RR, N));

        if (prec_RR != NULL) {
            *prec_RR = RR;
        }
    } else {
        MBEDTLS_MPI_CHK(mbedtls_mpi_grow(prec_RR, N->n));
        RR = *prec_RR;
    }

    /*
     * To preserve constness we need to make a copy of A. Using X for this to
```

## Snippet 33

```c
X->s = mbedtls_ct_mpi_sign_if(is_x_non_zero, -1, 1);

        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X, N, X));
    }

cleanup:

    mbedtls_mpi_zeroize_and_free(T, T_limbs);

    if (prec_RR == NULL || prec_RR->p == NULL) {
        mbedtls_mpi_free(&RR);
    }

    return ret;
}

int mbedtls_mpi_exp_mod(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *E, const mbedtls_mpi *N,
                        mbedtls_mpi *prec_RR)
{
    return mbedtls_mpi_exp_mod_optionally_safe(X, A, E, MBEDTLS_MPI_IS_SECRET, N, prec_RR);
}

int mbedtls_mpi_exp_mod_unsafe(mbedtls_mpi *X, const mbedtls_mpi *A,
                               const mbedtls_mpi *E, const mbedtls_mpi *N,
                               mbedtls_mpi *prec_RR)
{
    return mbedtls_mpi_exp_mod_optionally_safe(X, A, E, MBEDTLS_MPI_IS_PUBLIC, N, prec_RR);
```

## Snippet 34

```c
mbedtls_mpi_get_bit(N, 0) != 1 ||
        (I != NULL && mbedtls_mpi_cmp_int(N, 1) == 0)) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    /* Check aliasing requirements */
    if (A == N || (I != NULL && (I == N || G == N))) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&local_g);

    if (G == NULL) {
        G = &local_g;
    }

    /* We can't modify the values of G or I before use in the main function,
     * as they could be aliased to A or N. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(G, N->n));
    if (I != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_grow(I, N->n));
    }

    T = mbedtls_calloc(sizeof(mbedtls_mpi_uint) * N->n, T_factor);
    if (T == NULL) {
        ret = MBEDTLS_ERR_MPI_ALLOC_FAILED;
        goto cleanup;
    }
```

## Snippet 35

```c
}

    if (G->n > N->n) {
        memset(G->p + N->n, 0, ciL * (G->n - N->n));
    }
    if (I != NULL && I->n > N->n) {
        memset(I->p + N->n, 0, ciL * (I->n - N->n));
    }

cleanup:
    mbedtls_mpi_free(&local_g);
    mbedtls_free(T);
    return ret;
}

/*
 * Greatest common divisor: G = gcd(A, B)
 * Wrapper around mbedtls_mpi_gcd_modinv() that removes its restrictions.
 */
int mbedtls_mpi_gcd(mbedtls_mpi *G, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi TA, TB;

    mbedtls_mpi_init(&TA); mbedtls_mpi_init(&TB);

    /* Make copies and take absolute values */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TA, A));
```

## Snippet 36

```c
/*
 * Greatest common divisor: G = gcd(A, B)
 * Wrapper around mbedtls_mpi_gcd_modinv() that removes its restrictions.
 */
int mbedtls_mpi_gcd(mbedtls_mpi *G, const mbedtls_mpi *A, const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi TA, TB;

    mbedtls_mpi_init(&TA); mbedtls_mpi_init(&TB);

    /* Make copies and take absolute values */
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TA, A));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&TB, B));
    TA.s = TB.s = 1;

    /* Make the two values the same (non-zero) number of limbs.
     * This is needed to use mbedtls_mpi_core functions below. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&TA, TB.n != 0 ? TB.n : 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(&TB, TA.n)); // non-zero from above

    /* Handle special cases (that don't happen in crypto usage) */
    if (mbedtls_mpi_core_check_zero_ct(TA.p, TA.n) == MBEDTLS_CT_FALSE) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(G, &TB)); // GCD(0, B) = abs(B)
        goto cleanup;
    }
    if (mbedtls_mpi_core_check_zero_ct(TB.p, TB.n) == MBEDTLS_CT_FALSE) {
```

## Snippet 37

```c
mbedtls_mpi_core_cond_swap(TA.p, TB.p, TA.n, swap);

    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(G, NULL, &TA, &TB));

    /* Re-inject the power of 2 we had previously put aside */
    size_t zg = za > zb ? zb : za; // zg = min(za, zb)
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(G, zg));

cleanup:

    mbedtls_mpi_free(&TA); mbedtls_mpi_free(&TB);

    return ret;
}

/*
 * Fill X with size bytes of random.
 * The bytes returned from the RNG are used in a specific order which
 * is suitable for deterministic ECDSA (see the specification of
 * mbedtls_mpi_random() and the implementation in mbedtls_mpi_fill_random()).
 */
int mbedtls_mpi_fill_random(mbedtls_mpi *X, size_t size,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const size_t limbs = CHARS_TO_LIMBS(size);
```

## Snippet 38

```c
/*
 * Modular inverse: X = A^-1 mod N with N odd (and A any range)
 */
int mbedtls_mpi_inv_mod_odd(mbedtls_mpi *X,
                            const mbedtls_mpi *A,
                            const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T, G;

    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&G);

    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, A, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &T, &T, N));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, &T));

cleanup:
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&G);

    return ret;
}
```

## Snippet 39

```c
* Modular inverse: X = A^-1 mod N with N odd (and A any range)
 */
int mbedtls_mpi_inv_mod_odd(mbedtls_mpi *X,
                            const mbedtls_mpi *A,
                            const mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T, G;

    mbedtls_mpi_init(&T);
    mbedtls_mpi_init(&G);

    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, A, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &T, &T, N));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, &T));

cleanup:
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&G);

    return ret;
}
```

## Snippet 40

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&T, A, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &T, &T, N));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, &T));

cleanup:
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&G);

    return ret;
}

/*
 * Compute X = A^-1 mod N with N even, A odd and 1 < A < N.
 *
 * This is not obvious because our constant-time modinv function only works with
 * an odd modulus, and here the modulus is even. The idea is that computing a
 * a^-1 mod b is really just computing the u coefficient in the Bézout relation
 * a*u + b*v = 1 (assuming gcd(a,b) = 1, i.e. the inverse exists). But if we know
 * one of u, v in this relation then the other is easy to find. So we can
 * actually start by computing N^-1 mod A with gives us "the wrong half" of the
 * Bézout relation, from which we'll deduce the interesting half A^-1 mod N.
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
```

## Snippet 41

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &T, &T, N));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, &T));

cleanup:
    mbedtls_mpi_free(&T);
    mbedtls_mpi_free(&G);

    return ret;
}

/*
 * Compute X = A^-1 mod N with N even, A odd and 1 < A < N.
 *
 * This is not obvious because our constant-time modinv function only works with
 * an odd modulus, and here the modulus is even. The idea is that computing a
 * a^-1 mod b is really just computing the u coefficient in the Bézout relation
 * a*u + b*v = 1 (assuming gcd(a,b) = 1, i.e. the inverse exists). But if we know
 * one of u, v in this relation then the other is easy to find. So we can
 * actually start by computing N^-1 mod A with gives us "the wrong half" of the
 * Bézout relation, from which we'll deduce the interesting half A^-1 mod N.
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
```

## Snippet 42

```c
*
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
int mbedtls_mpi_inv_mod_even_in_range(mbedtls_mpi *X,
                                      mbedtls_mpi const *A,
                                      mbedtls_mpi const *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi I, G;

    mbedtls_mpi_init(&I);
    mbedtls_mpi_init(&G);

    /* Set I = N^-1 mod A */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&I, N, A));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &I, &I, A));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    /* We know N * I = 1 + k * A for some k, which we can easily compute
     * as k = (N*I - 1) / A (we know there will be no remainder). */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&I, &I, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&I, &I, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&G, NULL, &I, A));

    /* Now we have a Bézout relation N * (previous value of I) - G * A = 1,
```

## Snippet 43

```c
* Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
int mbedtls_mpi_inv_mod_even_in_range(mbedtls_mpi *X,
                                      mbedtls_mpi const *A,
                                      mbedtls_mpi const *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi I, G;

    mbedtls_mpi_init(&I);
    mbedtls_mpi_init(&G);

    /* Set I = N^-1 mod A */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&I, N, A));
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(&G, &I, &I, A));
    if (mbedtls_mpi_cmp_int(&G, 1) != 0) {
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }

    /* We know N * I = 1 + k * A for some k, which we can easily compute
     * as k = (N*I - 1) / A (we know there will be no remainder). */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&I, &I, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&I, &I, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&G, NULL, &I, A));

    /* Now we have a Bézout relation N * (previous value of I) - G * A = 1,
     * so A^-1 mod N is -G mod N, which is N - G.
```

## Snippet 44

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&I, &I, N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&I, &I, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&G, NULL, &I, A));

    /* Now we have a Bézout relation N * (previous value of I) - G * A = 1,
     * so A^-1 mod N is -G mod N, which is N - G.
     * Note that 0 < k < N since 0 < I < A, so G (k) is already in range. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X, N, &G));

cleanup:
    mbedtls_mpi_free(&I);
    mbedtls_mpi_free(&G);
    return ret;
}

/*
 * Compute X = A^-1 mod N with N even and A odd (but in any range).
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
static int mbedtls_mpi_inv_mod_even(mbedtls_mpi *X,
                                    mbedtls_mpi const *A,
                                    mbedtls_mpi const *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi AA;

    mbedtls_mpi_init(&AA);
```

## Snippet 45

```c
MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&I, &I, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&G, NULL, &I, A));

    /* Now we have a Bézout relation N * (previous value of I) - G * A = 1,
     * so A^-1 mod N is -G mod N, which is N - G.
     * Note that 0 < k < N since 0 < I < A, so G (k) is already in range. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X, N, &G));

cleanup:
    mbedtls_mpi_free(&I);
    mbedtls_mpi_free(&G);
    return ret;
}

/*
 * Compute X = A^-1 mod N with N even and A odd (but in any range).
 *
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
static int mbedtls_mpi_inv_mod_even(mbedtls_mpi *X,
                                    mbedtls_mpi const *A,
                                    mbedtls_mpi const *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi AA;

    mbedtls_mpi_init(&AA);
```

## Snippet 46

```c
*
 * Return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE if the inverse doesn't exist.
 */
static int mbedtls_mpi_inv_mod_even(mbedtls_mpi *X,
                                    mbedtls_mpi const *A,
                                    mbedtls_mpi const *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi AA;

    mbedtls_mpi_init(&AA);

    /* Bring A in the range [0, N). */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&AA, A, N));

    /* We know A >= 0 but the next function wants A > 1 */
    int cmp = mbedtls_mpi_cmp_int(&AA, 1);
    if (cmp < 0) { // AA == 0
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }
    if (cmp == 0) { // AA = 1
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 1));
        goto cleanup;
    }

    /* Now we know 1 < A < N, N is even and AA is still odd */
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod_even_in_range(X, &AA, N));
```

## Snippet 47

```c
/* Bring A in the range [0, N). */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&AA, A, N));

    /* We know A >= 0 but the next function wants A > 1 */
    int cmp = mbedtls_mpi_cmp_int(&AA, 1);
    if (cmp < 0) { // AA == 0
        ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
        goto cleanup;
    }
    if (cmp == 0) { // AA = 1
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 1));
        goto cleanup;
    }

    /* Now we know 1 < A < N, N is even and AA is still odd */
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod_even_in_range(X, &AA, N));

cleanup:
    mbedtls_mpi_free(&AA);
    return ret;
}

/*
 * Modular inverse: X = A^-1 mod N
 *
 * Wrapper around mbedtls_mpi_gcd_modinv_odd() that lifts its limitations.
 */
int mbedtls_mpi_inv_mod(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N)
```

## Snippet 48

```c
}
    if (cmp == 0) { // AA = 1
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, 1));
        goto cleanup;
    }

    /* Now we know 1 < A < N, N is even and AA is still odd */
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod_even_in_range(X, &AA, N));

cleanup:
    mbedtls_mpi_free(&AA);
    return ret;
}

/*
 * Modular inverse: X = A^-1 mod N
 *
 * Wrapper around mbedtls_mpi_gcd_modinv_odd() that lifts its limitations.
 */
int mbedtls_mpi_inv_mod(mbedtls_mpi *X, const mbedtls_mpi *A, const mbedtls_mpi *N)
{
    if (mbedtls_mpi_cmp_int(N, 1) <= 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_get_bit(N, 0) == 1) {
        return mbedtls_mpi_inv_mod_odd(X, A, N);
    }
```

## Snippet 49

```c
* Miller-Rabin pseudo-primality test  (HAC 4.24)
 */
static int mpi_miller_rabin(const mbedtls_mpi *X, size_t rounds,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret, count;
    size_t i, j, k, s;
    mbedtls_mpi W, R, T, A, RR;

    mbedtls_mpi_init(&W); mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&T); mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&RR);

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&W, X, 1));
    s = mbedtls_mpi_lsb(&W);
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&R, &W));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&R, s));

    for (i = 0; i < rounds; i++) {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        count = 0;
```

## Snippet 50

```c
*/
static int mpi_miller_rabin(const mbedtls_mpi *X, size_t rounds,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret, count;
    size_t i, j, k, s;
    mbedtls_mpi W, R, T, A, RR;

    mbedtls_mpi_init(&W); mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&T); mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&RR);

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&W, X, 1));
    s = mbedtls_mpi_lsb(&W);
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&R, &W));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&R, s));

    for (i = 0; i < rounds; i++) {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        count = 0;
        do {
```

## Snippet 51

```c
static int mpi_miller_rabin(const mbedtls_mpi *X, size_t rounds,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    int ret, count;
    size_t i, j, k, s;
    mbedtls_mpi W, R, T, A, RR;

    mbedtls_mpi_init(&W); mbedtls_mpi_init(&R);
    mbedtls_mpi_init(&T); mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&RR);

    /*
     * W = |X| - 1
     * R = W >> lsb( W )
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&W, X, 1));
    s = mbedtls_mpi_lsb(&W);
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&R, &W));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&R, s));

    for (i = 0; i < rounds; i++) {
        /*
         * pick a random A, 1 < A < |X| - 1
         */
        count = 0;
        do {
            MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&A, X->n * ciL, f_rng, p_rng));
```

## Snippet 52

```c
* not prime if A != |X| - 1 or A == 1
         */
        if (mbedtls_mpi_cmp_mpi(&A, &W) != 0 ||
            mbedtls_mpi_cmp_int(&A,  1) == 0) {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    mbedtls_mpi_free(&W); mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&T); mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&RR);

    return ret;
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int mbedtls_mpi_is_prime_ext(const mbedtls_mpi *X, int rounds,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi XX;

    XX.s = 1;
```

## Snippet 53

```c
*/
        if (mbedtls_mpi_cmp_mpi(&A, &W) != 0 ||
            mbedtls_mpi_cmp_int(&A,  1) == 0) {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    mbedtls_mpi_free(&W); mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&T); mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&RR);

    return ret;
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int mbedtls_mpi_is_prime_ext(const mbedtls_mpi *X, int rounds,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi XX;

    XX.s = 1;
    XX.n = X->n;
```

## Snippet 54

```c
if (mbedtls_mpi_cmp_mpi(&A, &W) != 0 ||
            mbedtls_mpi_cmp_int(&A,  1) == 0) {
            ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
            break;
        }
    }

cleanup:
    mbedtls_mpi_free(&W); mbedtls_mpi_free(&R);
    mbedtls_mpi_free(&T); mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&RR);

    return ret;
}

/*
 * Pseudo-primality test: small factors, then Miller-Rabin
 */
int mbedtls_mpi_is_prime_ext(const mbedtls_mpi *X, int rounds,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi XX;

    XX.s = 1;
    XX.n = X->n;
    XX.p = X->p;
```

## Snippet 55

```c
int ret = MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    size_t k, n;
    int rounds;
    mbedtls_mpi_uint r;
    mbedtls_mpi Y;

    if (nbits < 3 || nbits > MBEDTLS_MPI_MAX_BITS) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&Y);

    n = BITS_TO_LIMBS(nbits);

    if ((flags & MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR) == 0) {
        /*
         * 2^-80 error probability, number of rounds chosen per HAC, table 4.4
         */
        rounds = ((nbits >= 1300) ?  2 : (nbits >=  850) ?  3 :
                  (nbits >=  650) ?  4 : (nbits >=  350) ?  8 :
                  (nbits >=  250) ? 12 : (nbits >=  150) ? 18 : 27);
    } else {
        /*
         * 2^-100 error probability, number of rounds computed based on HAC,
         * fact 4.48
         */
        rounds = ((nbits >= 1450) ?  4 : (nbits >=  1150) ?  5 :
                  (nbits >= 1000) ?  6 : (nbits >=   850) ?  7 :
```

## Snippet 56

```c
* so up Y by 6 and X by 12.
                 */
                MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(X,  X, 12));
                MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&Y, &Y, 6));
            }
        }
    }

cleanup:

    mbedtls_mpi_free(&Y);

    return ret;
}

#endif /* MBEDTLS_GENPRIME */


#if defined(MBEDTLS_ASN1_WRITE_C)
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
int mbedtls_asn1_write_mpi(unsigned char **p, const unsigned char *start, const mbedtls_mpi *X)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    // Write the MPI
    //
```

## Snippet 57

```c
* as 0 digits. We need to end up with 020100, not with 0200. */
    if (len == 0) {
        len = 1;
    }

    if (*p < start || (size_t) (*p - start) < len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }

    (*p) -= len;
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(X, *p, len));

    // DER format assumes 2s complement for numbers, so the leftmost bit
    // should be 0 for positive numbers and 1 for negative numbers.
    //
    if (X->s == 1 && **p & 0x80) {
        if (*p - start < 1) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }

        *--(*p) = 0x00;
        len += 1;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_INTEGER));

    ret = (int) len;
```

## Snippet 58

```c
};

/*
 * Checkup routine
 */
int mbedtls_mpi_self_test(int verbose)
{
    int ret, i;
    mbedtls_mpi A, E, N, X, Y, U, V;

    mbedtls_mpi_init(&A); mbedtls_mpi_init(&E); mbedtls_mpi_init(&N); mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y); mbedtls_mpi_init(&U); mbedtls_mpi_init(&V);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&A, 16,
                                            "EFE021C2645FD1DC586E69184AF4A31E" \
                                            "D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
```

## Snippet 59

```c
/*
 * Checkup routine
 */
int mbedtls_mpi_self_test(int verbose)
{
    int ret, i;
    mbedtls_mpi A, E, N, X, Y, U, V;

    mbedtls_mpi_init(&A); mbedtls_mpi_init(&E); mbedtls_mpi_init(&N); mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y); mbedtls_mpi_init(&U); mbedtls_mpi_init(&V);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&A, 16,
                                            "EFE021C2645FD1DC586E69184AF4A31E" \
                                            "D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));
```

## Snippet 60

```c
* Checkup routine
 */
int mbedtls_mpi_self_test(int verbose)
{
    int ret, i;
    mbedtls_mpi A, E, N, X, Y, U, V;

    mbedtls_mpi_init(&A); mbedtls_mpi_init(&E); mbedtls_mpi_init(&N); mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y); mbedtls_mpi_init(&U); mbedtls_mpi_init(&V);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&A, 16,
                                            "EFE021C2645FD1DC586E69184AF4A31E" \
                                            "D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X, &A, &N));
```

## Snippet 61

```c
mbedtls_mpi_init(&A); mbedtls_mpi_init(&E); mbedtls_mpi_init(&N); mbedtls_mpi_init(&X);
    mbedtls_mpi_init(&Y); mbedtls_mpi_init(&U); mbedtls_mpi_init(&V);

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&A, 16,
                                            "EFE021C2645FD1DC586E69184AF4A31E" \
                                            "D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "602AB7ECA597A3D6B56FF9829A5E8B85" \
                                            "9E857EA95A03512E2BAE7391688D264A" \
                                            "A5663B0341DB9CCFD2C4C5F421FEC814" \
                                            "8001B72E848A38CAE1C65F78E56ABDEF" \
```

## Snippet 62

```c
"D5F53E93B5F123FA41680867BA110131" \
                                            "944FE7952E2517337780CB0DB80E61AA" \
                                            "E7C8DDC6C5C6AADEB34EB38A2F40D5E6"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&E, 16,
                                            "B2E7EFD37075B9F03FF989C7C5051C20" \
                                            "34D2A323810251127E7BF8625A4F49A5" \
                                            "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "602AB7ECA597A3D6B56FF9829A5E8B85" \
                                            "9E857EA95A03512E2BAE7391688D264A" \
                                            "A5663B0341DB9CCFD2C4C5F421FEC814" \
                                            "8001B72E848A38CAE1C65F78E56ABDEF" \
                                            "E12D3C039B8A02D6BE593F0BBBDA56F1" \
                                            "ECF677152EF804370C1A305CAF3B5BF1" \
                                            "30879B56C61DE584A0F53A2447A51E"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #1 (mul_mpi): ");
```

## Snippet 63

```c
"F3E27F4DA8BD59C47D6DAABA4C8127BD" \
                                            "5B5C25763222FEFCCFC38B832366C29E"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&N, 16,
                                            "0066A198186C18C10B2F5ED9B522752A" \
                                            "9830B69916E535C8F047518A889A43A5" \
                                            "94B6BED27A168D31D4A52F88925AA8F5"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&X, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "602AB7ECA597A3D6B56FF9829A5E8B85" \
                                            "9E857EA95A03512E2BAE7391688D264A" \
                                            "A5663B0341DB9CCFD2C4C5F421FEC814" \
                                            "8001B72E848A38CAE1C65F78E56ABDEF" \
                                            "E12D3C039B8A02D6BE593F0BBBDA56F1" \
                                            "ECF677152EF804370C1A305CAF3B5BF1" \
                                            "30879B56C61DE584A0F53A2447A51E"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #1 (mul_mpi): ");
    }

    if (mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
```

## Snippet 64

```c
ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&X, &Y, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "256567336059E52CAE22925474705F39A94"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&V, 16,
                                            "6613F26162223DF488E9CD48CC132C7A" \
                                            "0AC93C701B001B092E4E5B9F73BCD27B" \
                                            "9EE50D0657C77F374E903CDFA4C642"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #2 (div_mpi): ");
    }

    if (mbedtls_mpi_cmp_mpi(&X, &U) != 0 ||
        mbedtls_mpi_cmp_mpi(&Y, &V) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }
```

## Snippet 65

```c
if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&X, &Y, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "256567336059E52CAE22925474705F39A94"));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&V, 16,
                                            "6613F26162223DF488E9CD48CC132C7A" \
                                            "0AC93C701B001B092E4E5B9F73BCD27B" \
                                            "9EE50D0657C77F374E903CDFA4C642"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #2 (div_mpi): ");
    }

    if (mbedtls_mpi_cmp_mpi(&X, &U) != 0 ||
        mbedtls_mpi_cmp_mpi(&Y, &V) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }
```

## Snippet 66

```c
ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&X, &A, &E, &N, NULL));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "36E139AEA55215609D2816998ED020BB" \
                                            "BD96C37890F65171D948E9BC7CBAA4D9" \
                                            "325D24D6A3C12710F10A09FA08AB87"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #3 (exp_mod): ");
    }

    if (mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }
```

## Snippet 67

```c
ret = 1;
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&X, &A, &N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&U, 16,
                                            "003A0AAEDD7E784FC07D8F9EC6E3BFD5" \
                                            "C3DBA76456363A10869622EAC2DD84EC" \
                                            "C5B8A74DAC4D09E03B5E0BE779F2DF61"));

    if (verbose != 0) {
        mbedtls_printf("  MPI test #4 (inv_mod): ");
    }

    if (mbedtls_mpi_cmp_mpi(&X, &U) != 0) {
        if (verbose != 0) {
            mbedtls_printf("failed\n");
        }

        ret = 1;
        goto cleanup;
    }
```

## Snippet 68

```c
if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        mbedtls_printf("  MPI test #5 (simple gcd): ");
    }

    for (i = 0; i < GCD_PAIR_COUNT; i++) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&X, gcd_pairs[i][0]));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&Y, gcd_pairs[i][1]));

        MBEDTLS_MPI_CHK(mbedtls_mpi_gcd(&A, &X, &Y));

        if (mbedtls_mpi_cmp_int(&A, gcd_pairs[i][2]) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed at %d\n", i);
            }

            ret = 1;
            goto cleanup;
        }
    }

    if (verbose != 0) {
        mbedtls_printf("passed\n");
    }
```

## Snippet 69

```c
if (verbose != 0) {
        mbedtls_printf("passed\n");
    }

cleanup:

    if (ret != 0 && verbose != 0) {
        mbedtls_printf("Unexpected error, return code = %08X\n", (unsigned int) ret);
    }

    mbedtls_mpi_free(&A); mbedtls_mpi_free(&E); mbedtls_mpi_free(&N); mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y); mbedtls_mpi_free(&U); mbedtls_mpi_free(&V);

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return ret;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_BIGNUM_C */
```

## Snippet 70

```c
mbedtls_printf("passed\n");
    }

cleanup:

    if (ret != 0 && verbose != 0) {
        mbedtls_printf("Unexpected error, return code = %08X\n", (unsigned int) ret);
    }

    mbedtls_mpi_free(&A); mbedtls_mpi_free(&E); mbedtls_mpi_free(&N); mbedtls_mpi_free(&X);
    mbedtls_mpi_free(&Y); mbedtls_mpi_free(&U); mbedtls_mpi_free(&V);

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return ret;
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_BIGNUM_C */
```

