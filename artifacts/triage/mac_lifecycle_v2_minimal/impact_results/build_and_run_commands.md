# Build and run commands for MAC lifecycle impact demos

## OpenSSL impact demo

    OPENSSL_ROOT=/home/whisper/work/clean_sources/openssl-3.5.5

    clang -g -O0 -Wall -Wextra \
      -I"$OPENSSL_ROOT/include" \
      artifacts/triage/mac_lifecycle_v2_minimal/impact_cases/mac_state_machine_misuse_demo_openssl.c \
      -o artifacts/triage/mac_lifecycle_v2_minimal/impact_build/mac_state_machine_misuse_demo_openssl \
      -L"$OPENSSL_ROOT" \
      -Wl,-rpath,"$OPENSSL_ROOT" \
      -lcrypto

    ./artifacts/triage/mac_lifecycle_v2_minimal/impact_build/mac_state_machine_misuse_demo_openssl \
      | tee artifacts/triage/mac_lifecycle_v2_minimal/impact_results/openssl_state_machine_misuse_demo_results.txt

## mbedTLS PSA impact demo

    MBEDTLS_ROOT=/home/whisper/work/clean_sources/mbedtls-4.1.0

    clang -g -O0 -Wall -Wextra \
      -I"$MBEDTLS_ROOT/tf-psa-crypto/include" \
      -I"$MBEDTLS_ROOT/tf-psa-crypto/drivers/builtin/include" \
      -I"$MBEDTLS_ROOT/include" \
      artifacts/triage/mac_lifecycle_v2_minimal/impact_cases/mac_state_machine_misuse_demo_mbedtls.c \
      -o artifacts/triage/mac_lifecycle_v2_minimal/impact_build/mac_state_machine_misuse_demo_mbedtls \
      -Wl,--start-group \
      "$MBEDTLS_ROOT/build/library/libmbedcrypto.a" \
      "$MBEDTLS_ROOT/build/library/libtfpsacrypto.a" \
      -Wl,--end-group

    ./artifacts/triage/mac_lifecycle_v2_minimal/impact_build/mac_state_machine_misuse_demo_mbedtls \
      | tee artifacts/triage/mac_lifecycle_v2_minimal/impact_results/mbedtls_state_machine_misuse_demo_results.txt

## Notes

The OpenSSL demo uses OpenSSL 3.5.5.

The mbedTLS PSA demo uses mbedTLS 4.1.0 with tf-psa-crypto headers and static libraries.

The key impact comparison is:

- OpenSSL: post-final update succeeds and the application accepts the post-finish data path.
- mbedTLS PSA: post-finish update returns PSA_ERROR_BAD_STATE and the application rejects the post-finish data path.
