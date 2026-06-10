# ASAN / UBSAN TODO

The current local OpenSSL build is not an ASAN / UBSAN build. I did not modify
the OpenSSL build system for this qualification sprint.

Recommended follow-up:

1. Build OpenSSL with ASAN / UBSAN enabled.
2. Recompile the three minimal reproducers against that build.
3. Rerun:
   - `pre_init_used_only`
   - `done_then_used`
   - `initialized_then_used_control`
4. Record sanitizer output under this `qualification/debug/` directory.
