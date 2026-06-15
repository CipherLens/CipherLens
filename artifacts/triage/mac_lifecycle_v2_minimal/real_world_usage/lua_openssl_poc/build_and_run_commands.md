# Build and run commands for lua-openssl CMAC lifecycle PoC

## Build lua-openssl against OpenSSL 3.5.5 static libcrypto

    cd ~/CipherLens/artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/repo_review/lua-openssl

    rm -rf build
    mkdir build
    cd build

    OPENSSL_ROOT=/home/whisper/work/clean_sources/openssl-3.5.5

    cmake .. \
      -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" \
      -DOPENSSL_INCLUDE_DIR="$OPENSSL_ROOT/include" \
      -DOPENSSL_CRYPTO_LIBRARY="$OPENSSL_ROOT/libcrypto.a" \
      -DLUA_INCLUDE_DIR=/usr/include/lua5.4 \
      -DLUA_LIBRARIES=/usr/lib/x86_64-linux-gnu/liblua5.4.so

    make -j"$(nproc)"

## Locate module

    find build -type f \( -name "*.so" -o -name "openssl.so" \)

Expected module:

    build/openssl.so

## Run PoC

    cd ~/CipherLens

    LUA_CPATH="$PWD/artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/repo_review/lua-openssl/build/?.so;;" \
    lua5.4 artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/lua_openssl_poc/cmac_post_final_update_poc.lua \
      | tee artifacts/triage/mac_lifecycle_v2_minimal/real_world_usage/lua_openssl_poc/cmac_post_final_update_poc_results_openssl_3_5_5_static.txt

