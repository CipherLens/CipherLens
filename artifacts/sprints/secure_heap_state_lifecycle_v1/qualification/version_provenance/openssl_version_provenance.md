# OpenSSL Version Provenance

## Actual Version

The `secure_heap_state_lifecycle_v1` sprint is linked against the local
`openssl-3.5.5` source/build tree.

```yaml
compile_header_version: OpenSSL 3.5.5 27 Jan 2026
runtime_OpenSSL_version: OpenSSL 3.5.5 27 Jan 2026
runtime_OpenSSL_version_num: 30500050
linked_libcrypto_path: ${CLEAN_SOURCES_ROOT}/openssl-3.5.5/libcrypto.a
runtime_loaded_libcrypto_path: none observed by ldd
source_tree_path: ${CLEAN_SOURCES_ROOT}/openssl-3.5.5
confidence: high
```

## Evidence

The original sprint `run.jsonl` compile command uses:

```text
-I/home/wen/work/clean_sources/openssl-3.5.5/include
-L/home/wen/work/clean_sources/openssl-3.5.5
-Wl,-rpath,/home/wen/work/clean_sources/openssl-3.5.5
-lcrypto -lssl
```

The local OpenSSL tree contains `libcrypto.a` and `libssl.a`, not
`libcrypto.so`. `ldd` on the runner binaries and version probe does not list
`libcrypto.so`, which indicates static archive linkage into the executable.

The version probe prints:

```text
OPENSSL_VERSION_TEXT(header): OpenSSL 3.5.5 27 Jan 2026
OpenSSL_version(runtime): OpenSSL 3.5.5 27 Jan 2026
OpenSSL_version_num(runtime): 30500050
OpenSSL_full_version(runtime): 3.5.5
```

Therefore the current crash result is not merely system OpenSSL 3.0.13 artifact
validation; it reproduces on the local `openssl-3.5.5` build.
