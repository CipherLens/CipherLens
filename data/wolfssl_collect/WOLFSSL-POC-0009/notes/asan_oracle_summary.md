# WOLFSSL-POC-0009 ASan Oracle Summary

## Vulnerable Signal

The vulnerable wolfSSL v5.8.4-stable build produces:

- ERROR: AddressSanitizer: heap-buffer-overflow
- WRITE of size 4
- wolfSSL_d2i_SSL_SESSION
- src/ssl_sess.c:2831
- SUMMARY: AddressSanitizer: heap-buffer-overflow
- ABORTING

The UBSan prelude also reports:

- runtime error: index 9 out of bounds for type 'x509_buffer [9]'
- src/ssl_sess.c:2831
- src/ssl_sess.c:2836

## Fixed / Current Signal

The fixed and current builds safely reject the mutated serialized session:

- wolfSSL_d2i_SSL_SESSION returned: (nil)
- cleanup done
- NO_ASAN_CRASH_OBSERVED
