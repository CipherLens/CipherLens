# ASN.1 Next Action

- next_task_name: `asn1_nested_boundary_minimal_reproducer_v1`
- proposed_path: `D_then_A`
- fallback: `asn1_nested_boundary_seed_enrichment_v1`

The next useful step is not A-path generation. First, recover or synthesize a minimal malformed PKCS12/ASN.1 input for `OPENSSL-ISSUE-30581`, then run ASAN/UBSAN/gdb validation against the intended OpenSSL version.

## GLM Usage

- current_sprint: `false`
- future_use: only after API mapping and oracle are stable
- allowed_role: `strict_recipe_slot_filling`
- forbidden_role: `free_form_c_generation`
