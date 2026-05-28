# Local Source Path Setup

This project expects local cryptographic-library source trees for compile/run
experiments. Runtime paths should not be hard-coded to one developer's home
directory.

## Recommended Layout

Use this directory layout when possible:

```text
work/
  crypto-pattern-fuzz/
  clean_sources/
    mbedtls-4.1.0/
    mbedtls-3.6.4/
    openssl-3.5.5/
    botan-3.10.0/
```

With this layout, no environment variable is required. The project defaults to:

```text
../clean_sources
```

relative to the repository root.

## Environment Override

If your source trees live somewhere else, set:

```bash
export CLEAN_SOURCES_ROOT=/your/path/to/clean_sources
```

The runtime config files use paths such as:

```text
${CLEAN_SOURCES_ROOT}/mbedtls-4.1.0/include
${CLEAN_SOURCES_ROOT}/openssl-3.5.5/include
```

If `CLEAN_SOURCES_ROOT` is unset, these expand to the default
`<project_root>/../clean_sources`.

## Quick Checks

Check that the runner CLI loads:

```bash
python3 -m runner.compile_run --help
```

Reproduce the MBEDTLS-POC-0020 RSA DER trailing-garbage experiment:

```bash
bash scripts/run_0020_rsa_der_pipeline.sh
```

If compilation fails because headers or libraries are missing, verify that your
`clean_sources` tree contains the expected library versions and that each
library has been built locally.
