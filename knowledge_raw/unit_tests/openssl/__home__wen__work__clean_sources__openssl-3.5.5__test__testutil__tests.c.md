# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/testutil/tests.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
test_fail_bignum_mono_message(NULL, file, line, "BIGNUM", "EVEN(", ")", s,
        a);
    return 0;
}

int test_BN_eq_word(const char *file, int line, const char *bns, const char *ws,
    const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw;

    if (a != NULL && BN_is_word(a, w))
        return 1;
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "==", a, bw);
    BN_free(bw);
    return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
```

## Call pattern 2

```c
a);
    return 0;
}

int test_BN_eq_word(const char *file, int line, const char *bns, const char *ws,
    const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw;

    if (a != NULL && BN_is_word(a, w))
        return 1;
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "==", a, bw);
    BN_free(bw);
    return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}
```

## Call pattern 3

```c
}

int test_BN_eq_word(const char *file, int line, const char *bns, const char *ws,
    const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw;

    if (a != NULL && BN_is_word(a, w))
        return 1;
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "==", a, bw);
    BN_free(bw);
    return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
```

## Call pattern 4

```c
BN_free(bw);
    return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
    int test_time_t_##opname(const char *file, int line,               \
        const char *s1, const char *s2,                                \
        const time_t t1, const time_t t2)                              \
    {                                                                  \
        ASN1_TIME *at1 = ASN1_TIME_set(NULL, t1);                      \
        ASN1_TIME *at2 = ASN1_TIME_set(NULL, t2);                      \
        int r = at1 != NULL && at2 != NULL                             \
            && ASN1_TIME_compare(at1, at2) op 0;                       \
        if (!r)                                                        \
            test_fail_message(NULL, file, line, "time_t", s1, s2, #op, \
                "[%s] compared to [%s]",                               \
                print_time(at1), print_time(at2));                     \
```

## Call pattern 5

```c
return 0;
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
    int test_time_t_##opname(const char *file, int line,               \
        const char *s1, const char *s2,                                \
        const time_t t1, const time_t t2)                              \
    {                                                                  \
        ASN1_TIME *at1 = ASN1_TIME_set(NULL, t1);                      \
        ASN1_TIME *at2 = ASN1_TIME_set(NULL, t2);                      \
        int r = at1 != NULL && at2 != NULL                             \
            && ASN1_TIME_compare(at1, at2) op 0;                       \
        if (!r)                                                        \
            test_fail_message(NULL, file, line, "time_t", s1, s2, #op, \
                "[%s] compared to [%s]",                               \
                print_time(at1), print_time(at2));                     \
        ASN1_STRING_free(at1);                                         \
```

## Call pattern 6

```c
}

int test_BN_abs_eq_word(const char *file, int line, const char *bns,
    const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
    int test_time_t_##opname(const char *file, int line,               \
        const char *s1, const char *s2,                                \
        const time_t t1, const time_t t2)                              \
    {                                                                  \
        ASN1_TIME *at1 = ASN1_TIME_set(NULL, t1);                      \
        ASN1_TIME *at2 = ASN1_TIME_set(NULL, t2);                      \
        int r = at1 != NULL && at2 != NULL                             \
            && ASN1_TIME_compare(at1, at2) op 0;                       \
        if (!r)                                                        \
            test_fail_message(NULL, file, line, "time_t", s1, s2, #op, \
                "[%s] compared to [%s]",                               \
                print_time(at1), print_time(at2));                     \
        ASN1_STRING_free(at1);                                         \
        ASN1_STRING_free(at2);                                         \
```

## Call pattern 7

```c
const char *ws, const BIGNUM *a, BN_ULONG w)
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
    int test_time_t_##opname(const char *file, int line,               \
        const char *s1, const char *s2,                                \
        const time_t t1, const time_t t2)                              \
    {                                                                  \
        ASN1_TIME *at1 = ASN1_TIME_set(NULL, t1);                      \
        ASN1_TIME *at2 = ASN1_TIME_set(NULL, t2);                      \
        int r = at1 != NULL && at2 != NULL                             \
            && ASN1_TIME_compare(at1, at2) op 0;                       \
        if (!r)                                                        \
            test_fail_message(NULL, file, line, "time_t", s1, s2, #op, \
                "[%s] compared to [%s]",                               \
                print_time(at1), print_time(at2));                     \
        ASN1_STRING_free(at1);                                         \
        ASN1_STRING_free(at2);                                         \
        return r;                                                      \
    }
DEFINE_TIME_T_COMPARISON(eq, ==)
```

## Call pattern 8

```c
{
    BIGNUM *bw, *aa;

    if (a != NULL && BN_abs_is_word(a, w))
        return 1;
    if ((aa = BN_dup(a)) != NULL)
        BN_set_negative(aa, 0);
    if ((bw = BN_new()) != NULL)
        BN_set_word(bw, w);
    test_fail_bignum_message(NULL, file, line, "BIGNUM", bns, ws, "abs==",
        aa, bw);
    BN_free(bw);
    BN_free(aa);
    return 0;
}

static const char *print_time(const ASN1_TIME *t)
{
    return t == NULL ? "<null>" : (const char *)ASN1_STRING_get0_data(t);
}

#define DEFINE_TIME_T_COMPARISON(opname, op)                           \
    int test_time_t_##opname(const char *file, int line,               \
        const char *s1, const char *s2,                                \
        const time_t t1, const time_t t2)                              \
    {                                                                  \
        ASN1_TIME *at1 = ASN1_TIME_set(NULL, t1);                      \
        ASN1_TIME *at2 = ASN1_TIME_set(NULL, t2);                      \
        int r = at1 != NULL && at2 != NULL                             \
            && ASN1_TIME_compare(at1, at2) op 0;                       \
        if (!r)                                                        \
            test_fail_message(NULL, file, line, "time_t", s1, s2, #op, \
                "[%s] compared to [%s]",                               \
                print_time(at1), print_time(at2));                     \
        ASN1_STRING_free(at1);                                         \
        ASN1_STRING_free(at2);                                         \
        return r;                                                      \
    }
DEFINE_TIME_T_COMPARISON(eq, ==)
DEFINE_TIME_T_COMPARISON(ne, !=)
```

