# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/params_test.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
"4142434445464748494a4b4c4d4e4f50" \
    "5152535455565758595a616263646566" \
    "6768696a6b6c6d6e6f70717273747576" \
    "7778797a30313233343536373839"
#define p4_init "BLAKE2s256" /* Random string */
#define p5_init "Hellow World" /* Random string */ /* codespell:ignore */
#define p6_init OPENSSL_FULL_VERSION_STR /* Static string */

static void cleanup_object(void *vobj)
{
    struct object_st *obj = vobj;

    BN_free(obj->p3);
    obj->p3 = NULL;
    OPENSSL_free(obj->p4);
    obj->p4 = NULL;
    OPENSSL_free(obj);
}

static void *init_object(void)
{
    struct object_st *obj;

    if (!TEST_ptr(obj = OPENSSL_zalloc(sizeof(*obj))))
        return NULL;

    obj->p1 = p1_init;
    obj->p2 = p2_init;
    if (!TEST_true(BN_hex2bn(&obj->p3, p3_init)))
        goto fail;
    if (!TEST_ptr(obj->p4 = OPENSSL_strdup(p4_init)))
        goto fail;
    strcpy(obj->p5, p5_init);
    obj->p6 = p6_init;

    return obj;
fail:
    cleanup_object(obj);
    obj = NULL;
```

## Call pattern 2

```c
*/

static int raw_set_params(void *vobj, const OSSL_PARAM *params)
{
    struct object_st *obj = vobj;

    for (; params->key != NULL; params++)
        if (strcmp(params->key, "p1") == 0) {
            obj->p1 = *(int *)params->data;
        } else if (strcmp(params->key, "p2") == 0) {
            obj->p2 = *(double *)params->data;
        } else if (strcmp(params->key, "p3") == 0) {
            BN_free(obj->p3);
            if (!TEST_ptr(obj->p3 = BN_native2bn(params->data,
                              params->data_size, NULL)))
                return 0;
        } else if (strcmp(params->key, "p4") == 0) {
            OPENSSL_free(obj->p4);
            if (!TEST_ptr(obj->p4 = OPENSSL_strndup(params->data,
                              params->data_size)))
                return 0;
            obj->p4_l = strlen(obj->p4);
        } else if (strcmp(params->key, "p5") == 0) {
            /*
             * Protect obj->p5 against too much data.  This should not
             * happen, we don't use that long strings.
             */
            size_t data_length = OPENSSL_strnlen(params->data, params->data_size);

            if (!TEST_size_t_lt(data_length, sizeof(obj->p5)))
                return 0;
            strncpy(obj->p5, params->data, data_length);
            obj->p5[data_length] = '\0';
            obj->p5_l = strlen(obj->p5);
        } else if (strcmp(params->key, "p6") == 0) {
            obj->p6 = *(const char **)params->data;
            obj->p6_l = params->data_size;
        }

    return 1;
```

## Call pattern 3

```c
static unsigned char foo[1]; /* "foo" */

#define app_p1_init 17 /* A random number */
#define app_p2_init 47.11 /* Another random number */
#define app_p3_init "deadbeef" /* Classic */
#define app_p4_init "Hello"
#define app_p5_init "World"
#define app_p6_init "Cookie"
#define app_foo_init 'z'

static int cleanup_app_variables(void)
{
    BN_free(app_p3);
    app_p3 = NULL;
    return 1;
}

static int init_app_variables(void)
{
    int l = 0;

    cleanup_app_variables();

    app_p1 = app_p1_init;
    app_p2 = app_p2_init;
    if (!BN_hex2bn(&app_p3, app_p3_init)
        || (l = BN_bn2nativepad(app_p3, bignumbin, sizeof(bignumbin))) < 0)
        return 0;
    strcpy(app_p4, app_p4_init);
    strcpy(app_p5, app_p5_init);
    app_p6 = app_p6_init;
    foo[0] = app_foo_init;

    return 1;
}

/*
 * Here, we define test OSSL_PARAM arrays
 */
```

## Call pattern 4

```c
|| !TEST_double_eq(sneakpeek->p2, p2_init) /* Should remain untouched */
            || !TEST_BN_eq(sneakpeek->p3, app_p3) /* app value set */
            || !TEST_str_eq(sneakpeek->p4, app_p4) /* app value set */
            || !TEST_str_eq(sneakpeek->p5, app_p5) /* app value set */
            || !TEST_str_eq(sneakpeek->p6, app_p6)) /* app value set */
            errcnt++;
    }

    /*
     * Get parameters again, checking that we get different values
     * than earlier where relevant.
     */
    BN_free(verify_p3);
    verify_p3 = NULL;

    if (!TEST_true(BN_hex2bn(&verify_p3, app_p3_init))) {
        errcnt++;
        goto fin;
    }

    if (!TEST_true(prov->get_params(obj, params))
        || !TEST_int_eq(app_p1, app_p1_init) /* app value */
        || !TEST_double_eq(app_p2, app_p2_init) /* Should remain untouched */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "p3"))
        || !TEST_ptr(BN_native2bn(bignumbin, p->return_size, app_p3))
        || !TEST_BN_eq(app_p3, verify_p3) /* app value */
        || !TEST_str_eq(app_p4, app_p4_init) /* app value */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "p5"))
        || !TEST_size_t_eq(p->return_size,
            sizeof(app_p5_init) - 1) /* app value */
        || !TEST_str_eq(app_p5, app_p5_init) /* app value */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "p6"))
        || !TEST_size_t_eq(p->return_size,
            sizeof(app_p6_init) - 1) /* app value */
        || !TEST_str_eq(app_p6, app_p6_init) /* app value */
        || !TEST_char_eq(foo[0], app_foo_init) /* Should remain untouched */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "foo")))
        errcnt++;

fin:
```

## Call pattern 5

```c
|| !TEST_size_t_eq(p->return_size,
            sizeof(app_p5_init) - 1) /* app value */
        || !TEST_str_eq(app_p5, app_p5_init) /* app value */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "p6"))
        || !TEST_size_t_eq(p->return_size,
            sizeof(app_p6_init) - 1) /* app value */
        || !TEST_str_eq(app_p6, app_p6_init) /* app value */
        || !TEST_char_eq(foo[0], app_foo_init) /* Should remain untouched */
        || !TEST_ptr(p = OSSL_PARAM_locate(params, "foo")))
        errcnt++;

fin:
    BN_free(verify_p3);
    verify_p3 = NULL;
    cleanup_app_variables();
    cleanup_object(obj);

    return errcnt == 0;
}

static int test_case(int i)
{
    TEST_info("Case: %s", test_cases[i].desc);

    return test_case_variant(test_cases[i].app->static_params,
               test_cases[i].prov)
        && (test_cases[i].app->constructed_params == NULL
            || test_case_variant(test_cases[i].app->constructed_params(),
                test_cases[i].prov));
}

/*-
 * OSSL_PARAM_allocate_from_text() tests
 * =====================================
 */

static const OSSL_PARAM params_from_text[] = {
    /* Fixed size buffer */
    OSSL_PARAM_int32("int", NULL),
    OSSL_PARAM_DEFN("short", OSSL_PARAM_INTEGER, NULL, sizeof(int16_t)),
```

