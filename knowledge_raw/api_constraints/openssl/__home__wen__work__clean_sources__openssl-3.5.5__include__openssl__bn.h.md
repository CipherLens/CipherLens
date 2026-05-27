# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/include/openssl/bn.h
Knowledge type: api_constraints

## Snippet 1

```c
#define BN_RAND_TOP_ONE 0
#define BN_RAND_TOP_TWO 1

/* Values for |bottom| in BN_rand() */
#define BN_RAND_BOTTOM_ANY 0
#define BN_RAND_BOTTOM_ODD 1

/*
 * get a clone of a BIGNUM with changed flags, for *temporary* use only (the
 * two BIGNUMs cannot be used in parallel!). Also only for *read only* use. The
 * value |dest| should be a newly allocated BIGNUM obtained via BN_new() that
 * has not been otherwise initialised or used.
 */
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);

/* Wrapper function to make using BN_GENCB easier */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);

BN_GENCB *BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *cb);

/* Populate a BN_GENCB structure with an "old"-style callback */
void BN_GENCB_set_old(BN_GENCB *gencb, void (*callback)(int, int, void *),
    void *cb_arg);

/* Populate a BN_GENCB structure with a "new"-style callback */
void BN_GENCB_set(BN_GENCB *gencb, int (*callback)(int, int, BN_GENCB *),
    void *cb_arg);
```

## Snippet 2

```c
#endif

#define BN_num_bytes(a) ((BN_num_bits(a) + 7) / 8)

int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_zero(const BIGNUM *a);
int BN_is_one(const BIGNUM *a);
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_odd(const BIGNUM *a);

#define BN_one(a) (BN_set_word((a), 1))

void BN_zero_ex(BIGNUM *a);

#if OPENSSL_API_LEVEL > 908
#define BN_zero(a) BN_zero_ex(a)
#else
#define BN_zero(a) (BN_set_word((a), 0))
#endif

const BIGNUM *BN_value_one(void);
char *BN_options(void);
BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *ctx);
BN_CTX *BN_CTX_new(void);
BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *ctx);
BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
```

## Snippet 3

```c
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_odd(const BIGNUM *a);

#define BN_one(a) (BN_set_word((a), 1))

void BN_zero_ex(BIGNUM *a);

#if OPENSSL_API_LEVEL > 908
#define BN_zero(a) BN_zero_ex(a)
#else
#define BN_zero(a) (BN_set_word((a), 0))
#endif

const BIGNUM *BN_value_one(void);
char *BN_options(void);
BN_CTX *BN_CTX_new_ex(OSSL_LIB_CTX *ctx);
BN_CTX *BN_CTX_new(void);
BN_CTX *BN_CTX_secure_new_ex(OSSL_LIB_CTX *ctx);
BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_priv_rand_ex(BIGNUM *rnd, int bits, int top, int bottom,
    unsigned int strength, BN_CTX *ctx);
```

## Snippet 4

```c
int BN_priv_rand_range(BIGNUM *rnd, const BIGNUM *range);
#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
OSSL_DEPRECATEDIN_3_0
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
#endif
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(BN_ULONG l);
int BN_security_bits(int L, int N);
BIGNUM *BN_new(void);
BIGNUM *BN_secure_new(void);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
```

## Snippet 5

```c
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(BN_ULONG l);
int BN_security_bits(int L, int N);
BIGNUM *BN_new(void);
BIGNUM *BN_secure_new(void);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
```

## Snippet 6

```c
int BN_num_bits_word(BN_ULONG l);
int BN_security_bits(int L, int N);
BIGNUM *BN_new(void);
BIGNUM *BN_secure_new(void);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2bin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2lebin(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *BN_signed_native2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
```

## Snippet 7

```c
int BN_bn2nativepad(const BIGNUM *a, unsigned char *to, int tolen);
int BN_signed_bn2native(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  b  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
int BN_is_negative(const BIGNUM *b);

int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
    BN_CTX *ctx);
#define BN_mod(rem, m, d, ctx) BN_div(NULL, (rem), (m), (d), (ctx))
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
```

## Snippet 8

```c
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
/** BN_set_negative sets sign of a BIGNUM
 * \param  b  pointer to the BIGNUM object
 * \param  n  0 if the BIGNUM b should be positive and a value != 0 otherwise
 */
void BN_set_negative(BIGNUM *b, int n);
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  b  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
int BN_is_negative(const BIGNUM *b);

int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d,
    BN_CTX *ctx);
#define BN_mod(rem, m, d, ctx) BN_div(NULL, (rem), (m), (d), (ctx))
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
```

## Snippet 9

```c
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m,
    BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);

BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUM *a);

int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
```

## Snippet 10

```c
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUM *a);

int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);

int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
```

## Snippet 11

```c
#endif
int BN_print(BIO *bio, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
char *BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);

/* Deprecated versions */
```

## Snippet 12

```c
int BN_print(BIO *bio, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
char *BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx); /* returns
                                                                  * -2 for
                                                                  * error */
int BN_are_coprime(BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret,
    const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);

void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);

/* Deprecated versions */
#ifndef OPENSSL_NO_DEPRECATED_0_9_8
```

