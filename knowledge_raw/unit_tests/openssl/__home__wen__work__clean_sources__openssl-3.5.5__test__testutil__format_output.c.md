# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/test/testutil/format_output.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
test_bignum_header_line();

    len = ((l1 > l2 ? l1 : l2) + bytes - 1) / bytes * bytes;

    if (len > MEM_BUFFER_SIZE && (bufp = OPENSSL_malloc(len * 2)) == NULL) {
        bufp = buffer;
        len = MEM_BUFFER_SIZE;
        test_printf_stderr("WARNING: these BIGNUMs have been truncated\n");
    }

    if (bn1 != NULL) {
        m1 = bufp;
        BN_bn2binpad(bn1, m1, len);
    }
    if (bn2 != NULL) {
        m2 = bufp + len;
        BN_bn2binpad(bn2, m2, len);
    }

    while (len > 0) {
        cnt = 8 * (len - bytes);
        n1 = convert_bn_memory(m1, bytes, b1, &lz1, bn1);
        n2 = convert_bn_memory(m2, bytes, b2, &lz2, bn2);

        diff = real_diff = 0;
        i = 0;
        p = bdiff;
        for (i = 0; b1[i] != '\0'; i++)
            if (b1[i] == b2[i] || b1[i] == ' ' || b2[i] == ' ') {
                *p++ = ' ';
                diff |= b1[i] != b2[i];
            } else {
                *p++ = '^';
                real_diff = diff = 1;
            }
        *p++ = '\0';
        if (!diff) {
            test_printf_stderr(" %s:% 5d\n", n2 > n1 ? b2 : b1, cnt);
        } else {
            if (cnt == 0 && bn1 == NULL)
```

## Call pattern 2

```c
if (len > MEM_BUFFER_SIZE && (bufp = OPENSSL_malloc(len * 2)) == NULL) {
        bufp = buffer;
        len = MEM_BUFFER_SIZE;
        test_printf_stderr("WARNING: these BIGNUMs have been truncated\n");
    }

    if (bn1 != NULL) {
        m1 = bufp;
        BN_bn2binpad(bn1, m1, len);
    }
    if (bn2 != NULL) {
        m2 = bufp + len;
        BN_bn2binpad(bn2, m2, len);
    }

    while (len > 0) {
        cnt = 8 * (len - bytes);
        n1 = convert_bn_memory(m1, bytes, b1, &lz1, bn1);
        n2 = convert_bn_memory(m2, bytes, b2, &lz2, bn2);

        diff = real_diff = 0;
        i = 0;
        p = bdiff;
        for (i = 0; b1[i] != '\0'; i++)
            if (b1[i] == b2[i] || b1[i] == ' ' || b2[i] == ' ') {
                *p++ = ' ';
                diff |= b1[i] != b2[i];
            } else {
                *p++ = '^';
                real_diff = diff = 1;
            }
        *p++ = '\0';
        if (!diff) {
            test_printf_stderr(" %s:% 5d\n", n2 > n1 ? b2 : b1, cnt);
        } else {
            if (cnt == 0 && bn1 == NULL)
                test_printf_stderr("-%s\n", b1);
            else if (cnt == 0 || n1 > 0)
                test_printf_stderr("-%s:% 5d\n", b1, cnt);
            if (cnt == 0 && bn2 == NULL)
```

## Call pattern 3

```c
test_printf_stderr("\n");
}

void test_output_bignum(const char *name, const BIGNUM *bn)
{
    if (bn == NULL || BN_is_zero(bn)) {
        test_printf_stderr("bignum: '%s' = %s\n", name,
            test_bignum_zero_null(bn));
    } else if (BN_num_bytes(bn) <= BN_OUTPUT_SIZE) {
        unsigned char buf[BN_OUTPUT_SIZE];
        char out[2 * sizeof(buf) + 1];
        char *p = out;
        int n = BN_bn2bin(bn, buf);

        hex_convert_memory(buf, n, p, BN_OUTPUT_SIZE);
        while (*p == '0' && *++p != '\0')
            ;
        test_printf_stderr("bignum: '%s' = %s0x%s\n", name,
            BN_is_negative(bn) ? "-" : "", p);
    } else {
        test_fail_bignum_common("bignum", NULL, 0, NULL, NULL, NULL, name,
            bn, bn);
    }
}

/* Memory output routines */

/*
 * Handle zero length blocks of memory or NULL pointers to memory
 */
static void test_memory_null_empty(const unsigned char *m, char c)
{
    if (m == NULL)
        test_printf_stderr("%4s %c%s\n", "", c, "NULL");
    else
        test_printf_stderr("%04x %c%s\n", 0u, c, "empty");
}

/*
 * Common code to display one or two blocks of memory.
```

