# DER Full-Consumption Misuse Scan

This triage scan checks whether callers of selected OpenSSL `d2i_*` APIs verify
that parsing consumed the full input buffer.

Scope:

- APIs: `d2i_PUBKEY`, `d2i_X509`, `d2i_X509_REQ`, `d2i_X509_CRL`,
  `d2i_PKCS8_PRIV_KEY_INFO`, `d2i_PKCS12`
- Source corpus: `openssl-3.5.5` plus repository PoC artifacts found by grep
- Output files:
  - `d2i_call_sites.txt`
  - `d2i_call_site_triage.csv`
  - `d2i_call_site_summary.json`
  - `potential_misuse_top.txt`

Classification summary:

- `checks_full_consumption`: caller appears to compare `p`/`derp`/similar
  against an end pointer or consumed length.
- `potential_misuse`: caller appears to check parse success, but no local
  full-consumption check was found.
- `prefix_parse_intended`: context suggests stream, BIO/FP, decoder, store, or
  multi-object parsing where prefix consumption may be intentional.
- `unknown_needs_manual_review`: local context is insufficient.

Important risk boundary:

- A low-level `d2i_*` function that accepts a DER prefix and advances `*ppin`
  is not itself necessarily a vulnerability.
- The risky pattern is a whole-input caller that treats non-NULL parse success
  as complete validation and does not check `p == end` or equivalent.
- Therefore, candidates here should be described as
  `API usage semantic candidate / pointer-consumption divergence`, not as an
  OpenSSL parser vulnerability by default.

Next validation step:

- Pick high-score rows from `potential_misuse_top.txt`.
- Build minimal caller-level harnesses with `valid_der + trailing_garbage`.
- Confirm whether the surrounding caller accepts the object as whole-input
  valid, or whether later logic rejects it.
