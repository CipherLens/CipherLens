# Triage Next Steps

Re-run `canary_decode_short_output` under the same local ASAN OpenSSL build. Check whether the short output buffer violates `EVP_DecodeBlock` contract; if so, downgrade to contract-boundary observation, otherwise keep as sanitizer candidate. Do not claim a confirmed vulnerability before contract review.
