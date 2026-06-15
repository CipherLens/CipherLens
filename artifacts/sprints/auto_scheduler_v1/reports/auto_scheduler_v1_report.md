# auto_scheduler_v1 Report

- Family count: `12`
- Top-1: `x509_parsing`
- Top-2: `evp_pkey_context_lifecycle`
- Top-3: `der_full_consumption`
- Recommended next task: `x509_parsing_triage_v1`
- Pattern Bank write-back: `false`
- Auto render/run: `false` / `false`
- Vulnerability found: `false`

## Why Not Previous Families

secure_heap: Moved to external validation after current-version init_failed_then_query
  candidate; not main exploratory top-1.
cipher_aead_lifecycle: GCM cases closed or demoted as legal semantics/mapping gaps;
  non-GCM spaces can wait.
asn1_nested_boundary: Blocked by real seed missing / placeholder-only evidence.
der_full_consumption: Strong app-level candidate, but next step is minimal reproducer/upstream
  inquiry rather than another scheduler-selected experiment.
mac_lifecycle: Successful A-path template; useful as reference, not urgent next discovery
  loop target.

## Gate Effects

blocked seed-missing and weak-evidence families; legal semantics negative feedback demotes AEAD-GCM.

GLM is allowed only for MAC lifecycle A-path template, but auto render/run remains disabled in this scheduler-only sprint.
