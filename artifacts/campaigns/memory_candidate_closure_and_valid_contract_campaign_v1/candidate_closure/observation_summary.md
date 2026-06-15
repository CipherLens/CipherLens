# Candidate Closure Summary

Three earlier memory-safety candidates are closed as contract-boundary observations:

- `EVP_EncodeBlock(NULL, nonzero length)` is invalid API use.
- `EVP_DecodeBlock` short output and input length mismatch are invalid contract / harness faults.
- `EVP_MAC_init(NULL, ...)` is outside the documented MAC context lifecycle.

The next campaign only promotes valid-contract crash, sanitizer, canary, or hang evidence.
