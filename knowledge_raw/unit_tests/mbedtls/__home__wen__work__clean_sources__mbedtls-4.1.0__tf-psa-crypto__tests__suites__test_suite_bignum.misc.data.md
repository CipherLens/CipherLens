# Official test/example call patterns: mbedtls

Library: mbedtls
Version: 4.1.0
Source file: /home/wen/work/clean_sources/mbedtls-4.1.0/tf-psa-crypto/tests/suites/test_suite_bignum.misc.data
Knowledge type: unit_tests_or_examples

## Call pattern 1

```c
Test mpi_write_string #10 (Negative hex with odd number of digits)
mpi_read_write_string:16:"-1":16:"":3:0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Provide NULL buffer with 0 length
mpi_zero_length_buffer_is_null

Base test mbedtls_mpi_read_binary #1
mpi_read_binary:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"0941379D00FED1491FE15DF284DFDE4A142F68AA8D412023195CEE66883E6290FFE703F4EA5963BF212713CEE46B107C09182B5EDCD955ADAC418BF4918E2889AF48E1099D513830CEC85C26AC1E158B52620E33BA8692F893EFBB2F958B4424"

Base test mbedtls_mpi_read_binary_le #1
mpi_read_binary_le:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448B952FBBEF93F89286BA330E62528B151EAC265CC8CE3038519D09E148AF89288E91F48B41ACAD55D9DC5E2B18097C106BE4CE132721BF6359EAF403E7FF90623E8866EE5C192320418DAA682F144ADEDF84F25DE11F49D1FE009D374109"

Base test mbedtls_mpi_write_binary #1
mpi_write_binary:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":100:0

Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
```

## Call pattern 2

```c
Provide NULL buffer with 0 length
mpi_zero_length_buffer_is_null

Base test mbedtls_mpi_read_binary #1
mpi_read_binary:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"0941379D00FED1491FE15DF284DFDE4A142F68AA8D412023195CEE66883E6290FFE703F4EA5963BF212713CEE46B107C09182B5EDCD955ADAC418BF4918E2889AF48E1099D513830CEC85C26AC1E158B52620E33BA8692F893EFBB2F958B4424"

Base test mbedtls_mpi_read_binary_le #1
mpi_read_binary_le:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448B952FBBEF93F89286BA330E62528B151EAC265CC8CE3038519D09E148AF89288E91F48B41ACAD55D9DC5E2B18097C106BE4CE132721BF6359EAF403E7FF90623E8866EE5C192320418DAA682F144ADEDF84F25DE11F49D1FE009D374109"

Base test mbedtls_mpi_write_binary #1
mpi_write_binary:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":100:0

Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
```

## Call pattern 3

```c
Base test mbedtls_mpi_read_binary #1
mpi_read_binary:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"0941379D00FED1491FE15DF284DFDE4A142F68AA8D412023195CEE66883E6290FFE703F4EA5963BF212713CEE46B107C09182B5EDCD955ADAC418BF4918E2889AF48E1099D513830CEC85C26AC1E158B52620E33BA8692F893EFBB2F958B4424"

Base test mbedtls_mpi_read_binary_le #1
mpi_read_binary_le:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448B952FBBEF93F89286BA330E62528B151EAC265CC8CE3038519D09E148AF89288E91F48B41ACAD55D9DC5E2B18097C106BE4CE132721BF6359EAF403E7FF90623E8866EE5C192320418DAA682F144ADEDF84F25DE11F49D1FE009D374109"

Base test mbedtls_mpi_write_binary #1
mpi_write_binary:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":100:0

Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
```

## Call pattern 4

```c
Base test mbedtls_mpi_read_binary_le #1
mpi_read_binary_le:"0941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448B952FBBEF93F89286BA330E62528B151EAC265CC8CE3038519D09E148AF89288E91F48B41ACAD55D9DC5E2B18097C106BE4CE132721BF6359EAF403E7FF90623E8866EE5C192320418DAA682F144ADEDF84F25DE11F49D1FE009D374109"

Base test mbedtls_mpi_write_binary #1
mpi_write_binary:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":100:0

Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
```

## Call pattern 5

```c
Base test mbedtls_mpi_write_binary #1
mpi_write_binary:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"000000000941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":100:0

Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
```

## Call pattern 6

```c
Test mbedtls_mpi_write_binary #1 (Buffer is larger)
mpi_write_binary:"123123123123123123123123123":"000123123123123123123123123123":15:0

Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
```

## Call pattern 7

```c
Test mbedtls_mpi_write_binary #1 (Buffer just fits)
mpi_write_binary:"123123123123123123123123123":"0123123123123123123123123123":14:0

Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
```

## Call pattern 8

```c
Test mbedtls_mpi_write_binary #2 (Buffer too small)
mpi_write_binary:"123123123123123123123123123":"23123123123123123123123123":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
mpi_read_file:"../framework/data_files/mpi_too_big":"":MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Base test mbedtls_mpi_write_file #1
```

## Call pattern 9

```c
Test mbedtls_mpi_write_binary: nonzero to NULL
mpi_write_binary:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
mpi_read_file:"../framework/data_files/mpi_too_big":"":MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Base test mbedtls_mpi_write_file #1
mpi_write_file:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"../framework/data_files/mpi_write"

Test mbedtls_mpi_lsb: 0 (null)
```

## Call pattern 10

```c
Test mbedtls_mpi_write_binary: 0 to NULL
mpi_write_binary:"00":"":0:0

Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
mpi_read_file:"../framework/data_files/mpi_too_big":"":MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Base test mbedtls_mpi_write_file #1
mpi_write_file:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"../framework/data_files/mpi_write"

Test mbedtls_mpi_lsb: 0 (null)
mpi_lsb:"":0

Test mbedtls_mpi_lsb: 0 (1 limb)
```

## Call pattern 11

```c
Base test mbedtls_mpi_write_binary_le #1
mpi_write_binary_le:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"24448b952fbbef93f89286ba330e62528b151eac265cc8ce3038519d09e148af89288e91f48b41acad55d9dc5e2b18097c106be4ce132721bf6359eaf403e7ff90623e8866ee5c192320418daa682f144adedf84f25de11f49d1fe009d37410900000000":100:0

Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
mpi_read_file:"../framework/data_files/mpi_too_big":"":MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Base test mbedtls_mpi_write_file #1
mpi_write_file:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"../framework/data_files/mpi_write"

Test mbedtls_mpi_lsb: 0 (null)
mpi_lsb:"":0

Test mbedtls_mpi_lsb: 0 (1 limb)
mpi_lsb:"0":0

Base test mbedtls_mpi_lsb #1
```

## Call pattern 12

```c
Test mbedtls_mpi_write_binary_le #1 (Buffer is larger)
mpi_write_binary_le:"123123123123123123123123123":"233112233112233112233112230100":15:0

Test mbedtls_mpi_write_binary_le #1 (Buffer just fits)
mpi_write_binary_le:"123123123123123123123123123":"2331122331122331122331122301":14:0

Test mbedtls_mpi_write_binary_le #2 (Buffer too small)
mpi_write_binary_le:"123123123123123123123123123":"23311223311223311223311223":13:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: nonzero to NULL
mpi_write_binary_le:"01":"":0:MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Test mbedtls_mpi_write_binary_le: 0 to NULL
mpi_write_binary_le:"00":"":0:0

Base test mbedtls_mpi_read_file #1
mpi_read_file:"../framework/data_files/mpi_16":"01f55332c3a48b910f9942f6c914e58bef37a47ee45cb164a5b6b8d1006bf59a059c21449939ebebfdf517d2e1dbac88010d7b1f141e997bd6801ddaec9d05910f4f2de2b2c4d714e2c14a72fc7f17aa428d59c531627f09":0

Test mbedtls_mpi_read_file #1 (Empty file)
mpi_read_file:"../framework/data_files/hash_file_4":"":MBEDTLS_ERR_MPI_FILE_IO_ERROR

Test mbedtls_mpi_read_file #2 (Illegal input)
mpi_read_file:"../framework/data_files/hash_file_2":"":0

Test mbedtls_mpi_read_file #3 (Input too big)
mpi_read_file:"../framework/data_files/mpi_too_big":"":MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL

Base test mbedtls_mpi_write_file #1
mpi_write_file:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":"../framework/data_files/mpi_write"

Test mbedtls_mpi_lsb: 0 (null)
mpi_lsb:"":0

Test mbedtls_mpi_lsb: 0 (1 limb)
mpi_lsb:"0":0

Base test mbedtls_mpi_lsb #1
mpi_lsb:"941379d00fed1491fe15df284dfde4a142f68aa8d412023195cee66883e6290ffe703f4ea5963bf212713cee46b107c09182b5edcd955adac418bf4918e2889af48e1099d513830cec85c26ac1e158b52620e33ba8692f893efbb2f958b4424":2

Base test mbedtls_mpi_lsb #2
```

