# Next Action After Minimal Reproducer

- decision: `seed_missing_placeholder_only`
- next_task_name: `asn1_nested_boundary_seed_enrichment_v1`
- proposed_path: `D_seed_recovery_before_A_path`

Strict reproduction is blocked because the original input `/tmp/pbmac1_null_salt.p12` is not present and the bundled `inputs/test.p12` is explicitly marked as placeholder input. Do not enter A-path until a real seed or equivalent minimized malformed PKCS12/ASN.1 input is recovered and validated.

## GLM Usage

- current_sprint: `false`
- future_use: only after strict reproduction or stable API mapping
- allowed_role: `strict_recipe_slot_filling`
- forbidden_role: `free_form_c_generation`
