# MBEDTLS-POC-0004 Candidate Notes

`candidate_mapper.py` does not yet have a dedicated rule for the
`return_code_outlen_semantic` / invalid-padding output-length family.

This round therefore uses a hand-written `candidates.yaml`. The rule should
later be promoted into `candidate_mapper.py` or a family-level registry so
similar error-path output-state PoCs can be scored consistently.

Candidate scoring focuses on:

- symmetric cipher finalization API;
- decrypt final padding check;
- caller-visible output length;
- return-code observability;
- invalid padding behavior;
- output length should remain zero on error.
