# pkey_parsing_seed_discovery_v1 Report

## Seed Discovery

- family: pkey_parsing
- candidate_seeds_found: 200
- verified_seed_count: 115
- seed_ready: True
- seed_formats: ['der', 'pem']

## OpenSSL

- openssl_path: /usr/bin/openssl
- openssl_version: OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)
- asan_openssl_available: False
- fallback_reason: /home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libssl.so.3: version `OPENSSL_3.4.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)
/home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libssl.so.3: version `OPENSSL_3.2.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)
/home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libcrypto.so.3: version `OPENSSL_3.2.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)
/home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libcrypto.so.3: version `OPENSSL_3.5.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)
/home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libcrypto.so.3: version `OPENSSL_3.3.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)
/home/wen/work/install-openssl-3.5.5-asan/bin/openssl: /lib/x86_64-linux-gnu/libcrypto.so.3: version `OPENSSL_3.4.0' not found (required by /home/wen/work/install-openssl-3.5.5-asan/bin/openssl)

## Next Stage

- next_stage: mutation_planner
- task_name: pkey_parsing_generic_mutation_plan_v1
- allowed_to_run_now: True
- blocked_by: []

## Policy

No tools script, family-specific seed discovery script, family-specific mutator,
fuzz harness render, fuzz harness compile, fuzz harness run, feedback, knowledge,
pattern-bank, adapter recipe, normalized template, GLM, git, CVE, exploitability,
or confirmed vulnerability claim was produced.

## Quality

- quality_status: pass
