# Official test/example call patterns: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/apps/prime.c
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
if (!generate && argc == 0) {
        BIO_printf(bio_err, "Missing number (s) to check\n");
        goto opthelp;
    }

    if (generate) {
        char *s;

        if (!bits) {
            BIO_printf(bio_err, "Specify the number of bits.\n");
            goto end;
        }
        bn = BN_new();
        if (bn == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        if (!BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL)) {
            BIO_printf(bio_err, "Failed to generate prime.\n");
            goto end;
        }
        s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
        if (s == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        BIO_printf(bio_out, "%s\n", s);
        OPENSSL_free(s);
    } else {
        for (; *argv; argv++) {
            int r = check_num(argv[0], hex);

            if (r)
                r = hex ? BN_hex2bn(&bn, argv[0]) : BN_dec2bn(&bn, argv[0]);

            if (!r) {
                BIO_printf(bio_err, "Failed to process value (%s)\n", argv[0]);
                goto end;
            }
```

## Call pattern 2

```c
BIO_printf(bio_err, "Specify the number of bits.\n");
            goto end;
        }
        bn = BN_new();
        if (bn == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        if (!BN_generate_prime_ex(bn, bits, safe, NULL, NULL, NULL)) {
            BIO_printf(bio_err, "Failed to generate prime.\n");
            goto end;
        }
        s = hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
        if (s == NULL) {
            BIO_printf(bio_err, "Out of memory.\n");
            goto end;
        }
        BIO_printf(bio_out, "%s\n", s);
        OPENSSL_free(s);
    } else {
        for (; *argv; argv++) {
            int r = check_num(argv[0], hex);

            if (r)
                r = hex ? BN_hex2bn(&bn, argv[0]) : BN_dec2bn(&bn, argv[0]);

            if (!r) {
                BIO_printf(bio_err, "Failed to process value (%s)\n", argv[0]);
                goto end;
            }

            BN_print(bio_out, bn);
            r = BN_check_prime(bn, NULL, NULL);
            if (r < 0) {
                BIO_printf(bio_err, "Error checking prime\n");
                goto end;
            }
            BIO_printf(bio_out, " (%s) %s prime\n",
                argv[0],
                r == 1 ? "is" : "is not");
```

## Call pattern 3

```c
if (r < 0) {
                BIO_printf(bio_err, "Error checking prime\n");
                goto end;
            }
            BIO_printf(bio_out, " (%s) %s prime\n",
                argv[0],
                r == 1 ? "is" : "is not");
        }
    }

    ret = 0;
end:
    BN_free(bn);
    return ret;
}
```

