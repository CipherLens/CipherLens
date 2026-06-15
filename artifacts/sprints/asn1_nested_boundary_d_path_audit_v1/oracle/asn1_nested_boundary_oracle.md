# ASN.1 Nested Boundary Oracle

- `safe_reject`: malformed nested child object should be rejected without crash.
- `full_consumption`: parser should not silently ignore malformed nested content if it belongs to the object.
- `no_crash`: malformed ASN.1 should not cause SIGSEGV / abort.
- `cross_library_semantic_divergence`: one library accepts nested malformed object while another rejects under comparable API.
- `app_level_validation_gap`: only used if behavior reaches CLI/app level.

This is not the DER full-consumption family. DER full-consumption is about trailing garbage after a valid top-level object; this family is about malformed children and nested boundary handling inside the object.
