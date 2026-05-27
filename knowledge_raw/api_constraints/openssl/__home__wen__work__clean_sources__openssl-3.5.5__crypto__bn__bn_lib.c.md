# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_lib.c
Knowledge type: api_constraints

## Snippet 1

```c
if (a == NULL)
        return;
    if (a->d != NULL && !BN_get_flags(a, BN_FLG_STATIC_DATA))
        bn_free_d(a, 1);
    if (BN_get_flags(a, BN_FLG_MALLOCED)) {
        OPENSSL_cleanse(a, sizeof(*a));
        OPENSSL_free(a);
    }
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    if (!BN_get_flags(a, BN_FLG_STATIC_DATA))
        bn_free_d(a, 0);
    if (a->flags & BN_FLG_MALLOCED)
        OPENSSL_free(a);
}

void bn_init(BIGNUM *a)
{
    static BIGNUM nilbn;

    *a = nilbn;
    bn_check_top(a);
}
```

## Snippet 2

```c
}

void bn_init(BIGNUM *a)
{
    static BIGNUM nilbn;

    *a = nilbn;
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
    BIGNUM *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    ret->flags = BN_FLG_MALLOCED;
    bn_check_top(ret);
    return ret;
}

BIGNUM *BN_secure_new(void)
{
    BIGNUM *ret = BN_new();

    if (ret != NULL)
        ret->flags |= BN_FLG_SECURE;
    return ret;
```

## Snippet 3

```c
if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    ret->flags = BN_FLG_MALLOCED;
    bn_check_top(ret);
    return ret;
}

BIGNUM *BN_secure_new(void)
{
    BIGNUM *ret = BN_new();

    if (ret != NULL)
        ret->flags |= BN_FLG_SECURE;
    return ret;
}

/* This is used by bn_expand2() */
/* The caller MUST check that words > b->dmax before calling this */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *a = NULL;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        ERR_raise(ERR_LIB_BN, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
```

## Snippet 4

```c
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_get_flags(a, BN_FLG_SECURE) ? BN_secure_new() : BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int bn_words;

    bn_check_top(b);

    bn_words = BN_get_flags(b, BN_FLG_CONSTTIME) ? b->dmax : b->top;
```

## Snippet 5

```c
BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_get_flags(a, BN_FLG_SECURE) ? BN_secure_new() : BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int bn_words;

    bn_check_top(b);

    bn_words = BN_get_flags(b, BN_FLG_CONSTTIME) ? b->dmax : b->top;

    if (a == b)
        return a;
    if (bn_wexpand(a, bn_words) == NULL)
```

## Snippet 6

```c
BN_ULONG BN_get_word(const BIGNUM *a)
{
    if (a->top > 1)
        return BN_MASK2;
    else if (a->top == 1)
        return a->d[0];
    /* a->top == 0 */
    return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    bn_check_top(a);
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return 0;
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    a->flags &= ~BN_FLG_FIXED_TOP;
    bn_check_top(a);
    return 1;
}

typedef enum { BIG,
    LITTLE } endianness_t;
typedef enum { SIGNED,
    UNSIGNED } signedness_t;
```

## Snippet 7

```c
int neg = 0, xor = 0, carry = 0;
    unsigned int i;
    unsigned int n;
    BIGNUM *bn = NULL;

    /* Negative length is not acceptable */
    if (len < 0)
        return NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return NULL;
    bn_check_top(ret);

    /*
     * If the input has no bits, the number is considered zero.
     * This makes calls with s==NULL and len==0 safe.
     */
    if (len == 0) {
        BN_clear(ret);
        return ret;
    }

    /*
     * The loop that does the work iterates from least to most
     * significant BIGNUM chunk, so we adapt parameters to transfer
     * input bytes accordingly.
```

## Snippet 8

```c
if (len == 0 || !(*s2 & 0x80))
            len++;
    }
    /* If it was all zeros, we're done */
    if (len == 0) {
        ret->top = 0;
        return ret;
    }
    n = ((len - 1) / BN_BYTES) + 1; /* Number of resulting bignum chunks */
    if (bn_wexpand(ret, (int)n) == NULL) {
        BN_free(bn);
        return NULL;
    }
    ret->top = n;
    ret->neg = neg;
    for (i = 0; n-- > 0; i++) {
        BN_ULONG l = 0; /* Accumulator */
        unsigned int m = 0; /* Offset in a bignum chunk, in bits */

        for (; len > 0 && m < BN_BYTES * 8; len--, s += inc, m += 8) {
            BN_ULONG byte_xored = *s ^ xor;
            BN_ULONG byte = (byte_xored + carry) & 0xff;

            carry = byte_xored > byte; /* Implicit 1 or 0 */
            l |= (byte << m);
        }
        ret->d[i] = l;
    }
```

## Snippet 9

```c
byte_xored = byte ^ xor;
        *to = (unsigned char)(byte_xored + carry);
        carry = byte_xored > *to; /* Implicit 1 or 0 */
        to += inc;
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}

int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, BIG, UNSIGNED);
}

int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, BIG, SIGNED);
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    return bn2binpad(a, to, -1, BIG, UNSIGNED);
}
```

## Snippet 10

```c
return bn2binpad(a, to, tolen, BIG, UNSIGNED);
}

int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, BIG, SIGNED);
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    return bn2binpad(a, to, -1, BIG, UNSIGNED);
}

BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    return bin2bn(s, len, ret, LITTLE, UNSIGNED);
}

BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    return bin2bn(s, len, ret, LITTLE, SIGNED);
}

int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
```

## Snippet 11

```c
return BN_signed_lebin2bn(s, len, ret);
    return BN_signed_bin2bn(s, len, ret);
}

int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        return BN_bn2lebinpad(a, to, tolen);
    return BN_bn2binpad(a, to, tolen);
}

int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen)
{
    DECLARE_IS_ENDIAN;

    if (IS_LITTLE_ENDIAN)
        return BN_signed_bn2lebin(a, to, tolen);
    return BN_signed_bn2bin(a, to, tolen);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    ap = a->d;
```

## Snippet 12

```c
{
    int ret;

    bn_check_top(a);
    ret = ossl_bn_mask_bits_fixed_top(a, n);
    if (ret)
        bn_correct_top(a);
    return ret;
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    if (n == 0)
        return 0;

    aa = a[n - 1];
    bb = b[n - 1];
```

