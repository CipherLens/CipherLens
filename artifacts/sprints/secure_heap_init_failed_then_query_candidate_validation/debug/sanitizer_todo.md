# Sanitizer TODO

No new ASAN/UBSAN OpenSSL build was created in this sprint. A future validation pass should rebuild or run with sanitizer-enabled OpenSSL, then rerun `init_failed_then_used`, `pre_init_used_seed_control`, and `initialized_then_used_safe_control`.
