# Official API knowledge snippets: openssl

Library: openssl
Version: 3.5.5
Source file: /home/wen/work/clean_sources/openssl-3.5.5/crypto/bn/bn_s390x.c
Knowledge type: api_constraints

## Snippet 1

```c
size = BN_num_bytes(m);
    buffer = OPENSSL_zalloc(4 * size);
    if (buffer == NULL)
        return 0;
    me.inputdata = buffer;
    me.inputdatalength = size;
    me.outputdata = buffer + size;
    me.outputdatalength = size;
    me.b_key = buffer + 2 * size;
    me.n_modulus = buffer + 3 * size;
    if (BN_bn2binpad(a, me.inputdata, size) == -1
        || BN_bn2binpad(p, me.b_key, size) == -1
        || BN_bn2binpad(m, me.n_modulus, size) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSAMODEXPO, &me) != -1) {
        if (BN_bin2bn(me.outputdata, size, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
```

## Snippet 2

```c
buffer = OPENSSL_zalloc(4 * size);
    if (buffer == NULL)
        return 0;
    me.inputdata = buffer;
    me.inputdatalength = size;
    me.outputdata = buffer + size;
    me.outputdatalength = size;
    me.b_key = buffer + 2 * size;
    me.n_modulus = buffer + 3 * size;
    if (BN_bn2binpad(a, me.inputdata, size) == -1
        || BN_bn2binpad(p, me.b_key, size) == -1
        || BN_bn2binpad(m, me.n_modulus, size) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSAMODEXPO, &me) != -1) {
        if (BN_bin2bn(me.outputdata, size, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
         * Make sure to not further use this hardware acceleration,
```

## Snippet 3

```c
if (buffer == NULL)
        return 0;
    me.inputdata = buffer;
    me.inputdatalength = size;
    me.outputdata = buffer + size;
    me.outputdatalength = size;
    me.b_key = buffer + 2 * size;
    me.n_modulus = buffer + 3 * size;
    if (BN_bn2binpad(a, me.inputdata, size) == -1
        || BN_bn2binpad(p, me.b_key, size) == -1
        || BN_bn2binpad(m, me.n_modulus, size) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSAMODEXPO, &me) != -1) {
        if (BN_bin2bn(me.outputdata, size, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
         * Make sure to not further use this hardware acceleration,
         * but do not close the file descriptor.
```

## Snippet 4

```c
part += 2 * size;
    crt.bp_key = part;
    part += size + 8;
    crt.bq_key = part;
    part += size;
    crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
```

## Snippet 5

```c
crt.bp_key = part;
    part += size + 8;
    crt.bq_key = part;
    part += size;
    crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
```

## Snippet 6

```c
part += size + 8;
    crt.bq_key = part;
    part += size;
    crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
```

## Snippet 7

```c
crt.bq_key = part;
    part += size;
    crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
```

## Snippet 8

```c
part += size;
    crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
         * Make sure to not further use this hardware acceleration,
```

## Snippet 9

```c
crt.np_prime = part;
    part += size + 8;
    crt.nq_prime = part;
    part += size;
    crt.u_mult_inv = part;
    if (BN_bn2binpad(i, crt.inputdata, crt.inputdatalength) == -1
        || BN_bn2binpad(p, crt.np_prime, size + 8) == -1
        || BN_bn2binpad(q, crt.nq_prime, size) == -1
        || BN_bn2binpad(dmp, crt.bp_key, size + 8) == -1
        || BN_bn2binpad(dmq, crt.bq_key, size) == -1
        || BN_bn2binpad(iqmp, crt.u_mult_inv, size + 8) == -1)
        goto dealloc;
    if (ioctl(OPENSSL_s390xcex, ICARSACRT, &crt) != -1) {
        if (BN_bin2bn(crt.outputdata, crt.outputdatalength, r) != NULL)
            res = 1;
    } else if (errno == EBADF || errno == ENOTTY) {
        /*
         * In this cases, someone (e.g. a sandbox) closed the fd.
         * Make sure to not further use this hardware acceleration.
         * In case of ENOTTY the file descriptor was already reused for another
         * file. Do not attempt to use or close that file descriptor anymore.
         */
        OPENSSL_s390xcex = -1;
    } else if (errno == ENODEV) {
        /*
         * No crypto card(s) available to handle RSA requests.
         * Make sure to not further use this hardware acceleration,
         * but do not close the file descriptor.
```

