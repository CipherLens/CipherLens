# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/srptest.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
Kserver = SRP_Calc_server_key(Apub, v, u, b, GN->N);
    test_output_bignum("Server's key", Kserver);

    if (!TEST_BN_eq(Kclient, Kserver))
        goto end;

    ret = 1;

end:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int check_bn(const char *name, const BIGNUM *bn, const char *hexbn)
{
    BIGNUM *tmp = NULL;
    int r;

    if (!TEST_true(BN_hex2bn(&tmp, hexbn)))
        return 0;

    if (BN_cmp(bn, tmp) != 0)
        TEST_error("unexpected %s value", name);
    r = TEST_BN_eq(bn, tmp);
    BN_free(tmp);
    return r;
}

/* SRP test vectors from RFC5054 */
static int run_srp_kat(void)
```

## Call pattern 2

```c
test_output_bignum("Server's key", Kserver);

    if (!TEST_BN_eq(Kclient, Kserver))
        goto end;

    ret = 1;

end:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int check_bn(const char *name, const BIGNUM *bn, const char *hexbn)
{
    BIGNUM *tmp = NULL;
    int r;

    if (!TEST_true(BN_hex2bn(&tmp, hexbn)))
        return 0;

    if (BN_cmp(bn, tmp) != 0)
        TEST_error("unexpected %s value", name);
    r = TEST_BN_eq(bn, tmp);
    BN_free(tmp);
    return r;
}

/* SRP test vectors from RFC5054 */
static int run_srp_kat(void)
{
```

## Call pattern 3

```c
if (!TEST_BN_eq(Kclient, Kserver))
        goto end;

    ret = 1;

end:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int check_bn(const char *name, const BIGNUM *bn, const char *hexbn)
{
    BIGNUM *tmp = NULL;
    int r;

    if (!TEST_true(BN_hex2bn(&tmp, hexbn)))
        return 0;

    if (BN_cmp(bn, tmp) != 0)
        TEST_error("unexpected %s value", name);
    r = TEST_BN_eq(bn, tmp);
    BN_free(tmp);
    return r;
}

/* SRP test vectors from RFC5054 */
static int run_srp_kat(void)
{
    int ret = 0;
    BIGNUM *s = NULL;
```

## Call pattern 4

```c
ret = 1;

end:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int check_bn(const char *name, const BIGNUM *bn, const char *hexbn)
{
    BIGNUM *tmp = NULL;
    int r;

    if (!TEST_true(BN_hex2bn(&tmp, hexbn)))
        return 0;

    if (BN_cmp(bn, tmp) != 0)
        TEST_error("unexpected %s value", name);
    r = TEST_BN_eq(bn, tmp);
    BN_free(tmp);
    return r;
}

/* SRP test vectors from RFC5054 */
static int run_srp_kat(void)
{
    int ret = 0;
    BIGNUM *s = NULL;
    BIGNUM *v = NULL;
    BIGNUM *a = NULL;
```

## Call pattern 5

```c
static int check_bn(const char *name, const BIGNUM *bn, const char *hexbn)
{
    BIGNUM *tmp = NULL;
    int r;

    if (!TEST_true(BN_hex2bn(&tmp, hexbn)))
        return 0;

    if (BN_cmp(bn, tmp) != 0)
        TEST_error("unexpected %s value", name);
    r = TEST_BN_eq(bn, tmp);
    BN_free(tmp);
    return r;
}

/* SRP test vectors from RFC5054 */
static int run_srp_kat(void)
{
    int ret = 0;
    BIGNUM *s = NULL;
    BIGNUM *v = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *u = NULL;
    BIGNUM *x = NULL;
    BIGNUM *Apub = NULL;
    BIGNUM *Bpub = NULL;
    BIGNUM *Kclient = NULL;
    BIGNUM *Kserver = NULL;
    /* use builtin 1024-bit params */
    const SRP_gN *GN;

    if (!TEST_ptr(GN = SRP_get_default_gN("1024")))
        goto err;
    BN_hex2bn(&s, "BEB25379D1A8581EB5A727673A2441EE");
    /* Set up server's password entry */
    if (!TEST_true(SRP_create_verifier_BN("alice", "password123", &s, &v, GN->N,
            GN->g)))
        goto err;
```

## Call pattern 6

```c
"41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F"
            "3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
            "C346D7E474B29EDE8A469FFECA686E5A")))
        goto err;
    TEST_note("    okay");

    ret = 1;

err:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int run_srp_tests(void)
{
    /* "Negative" test, expect a mismatch */
    TEST_info("run_srp: expecting a mismatch");
    if (!TEST_false(run_srp("alice", "password1", "password2")))
        return 0;

    /* "Positive" test, should pass */
    TEST_info("run_srp: expecting a match");
    if (!TEST_true(run_srp("alice", "password", "password")))
        return 0;

    return 1;
}
#endif

int setup_tests(void)
```

## Call pattern 7

```c
"3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212D"
            "C346D7E474B29EDE8A469FFECA686E5A")))
        goto err;
    TEST_note("    okay");

    ret = 1;

err:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int run_srp_tests(void)
{
    /* "Negative" test, expect a mismatch */
    TEST_info("run_srp: expecting a mismatch");
    if (!TEST_false(run_srp("alice", "password1", "password2")))
        return 0;

    /* "Positive" test, should pass */
    TEST_info("run_srp: expecting a match");
    if (!TEST_true(run_srp("alice", "password", "password")))
        return 0;

    return 1;
}
#endif

int setup_tests(void)
{
```

## Call pattern 8

```c
goto err;
    TEST_note("    okay");

    ret = 1;

err:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int run_srp_tests(void)
{
    /* "Negative" test, expect a mismatch */
    TEST_info("run_srp: expecting a mismatch");
    if (!TEST_false(run_srp("alice", "password1", "password2")))
        return 0;

    /* "Positive" test, should pass */
    TEST_info("run_srp: expecting a match");
    if (!TEST_true(run_srp("alice", "password", "password")))
        return 0;

    return 1;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SRP
    printf("No SRP support\n");
```

## Call pattern 9

```c
ret = 1;

err:
    BN_clear_free(Kclient);
    BN_clear_free(Kserver);
    BN_clear_free(x);
    BN_free(u);
    BN_free(Apub);
    BN_clear_free(a);
    BN_free(Bpub);
    BN_clear_free(b);
    BN_free(s);
    BN_clear_free(v);

    return ret;
}

static int run_srp_tests(void)
{
    /* "Negative" test, expect a mismatch */
    TEST_info("run_srp: expecting a mismatch");
    if (!TEST_false(run_srp("alice", "password1", "password2")))
        return 0;

    /* "Positive" test, should pass */
    TEST_info("run_srp: expecting a match");
    if (!TEST_true(run_srp("alice", "password", "password")))
        return 0;

    return 1;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_SRP
    printf("No SRP support\n");
#else
    ADD_TEST(run_srp_tests);
```

