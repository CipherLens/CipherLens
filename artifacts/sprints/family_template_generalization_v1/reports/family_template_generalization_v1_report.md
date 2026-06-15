# family_template_generalization_v1 report

- families: 5
- seeded packages: 2
- spec-only packages: 3
- canonical template families: pkcs_container_parsing, asn1_nested_boundary
- spec-only families: x509_parsing, tls_protocol_state_lifecycle, secure_heap_state_lifecycle
- avoided one PoC one template: yes
- tree-sitter AST mask pipeline success: True
- lite fallback used: False
- normalized write attempted: True
- normalized collisions: 5
- GLM called: no
- PoC/render/compile-run performed: no
- next_action: `adapter_recipe_generation_v1`

## Quality
- pkcs_container_parsing: pass (AST: ok)
- asn1_nested_boundary: pass (AST: ok)
- x509_parsing: spec_only_pass (AST: not_applicable_spec_only)
- tls_protocol_state_lifecycle: spec_only_pass (AST: not_applicable_spec_only)
- secure_heap_state_lifecycle: spec_only_pass (AST: not_applicable_spec_only)

No PoC execution, render, compile/run, GLM call, adapter generation, RAG rebuild, commit, or push was performed.
