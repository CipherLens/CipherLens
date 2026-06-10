# MAC lifecycle v2 minimal triage

This directory contains minimal confirmation cases for the six MAC lifecycle v2
triage signals observed in the generated recipe-slot pipeline.

The cases compare OpenSSL `EVP_MAC` CMAC lifecycle behavior with mbedTLS PSA MAC
operation lifecycle behavior for:

- `AES-128-CBC + update_after_final`
- `AES-128-CBC + third_final`
- `AES-128-CBC + update_after_second_final`
- `AES-256-CBC + update_after_final`
- `AES-256-CBC + third_final`
- `AES-256-CBC + update_after_second_final`

Interpretation:

- This is not a crash report.
- This is not a confirmed CVE.
- The current observation is a semantic difference between OpenSSL CMAC
  repeated-final / update-after-final behavior and mbedTLS PSA one-shot MAC
  operation lifecycle rejection behavior.
- `third_final` should remain `allowed_legacy_semantics_needs_review` until
  OpenSSL documentation confirms whether repeated CMAC finalization is intended
  legacy behavior.
- `update_after_final` and `update_after_second_final` remain high-value
  lifecycle semantic divergence candidates that need documentation review before
  any vulnerability claim.

Result summary:

- Normal and ASan/UBSan runs reproduced the same lifecycle behavior.
- `ASAN_OPTIONS=detect_leaks=0` was used for the sanitizer run because this
  execution environment reports LeakSanitizer ptrace incompatibility otherwise.
- No ASan, UBSan, SEGV, heap-buffer-overflow, stack-buffer-overflow, or
  use-after-free evidence was observed.
- OpenSSL CMAC accepted update-after-final and update-after-second-final
  continuation for both AES-128-CBC and AES-256-CBC.
- OpenSSL CMAC accepted third-final for both AES-128-CBC and AES-256-CBC.
- mbedTLS PSA rejected post-finish update and repeated finish paths with
  status `-137`.
