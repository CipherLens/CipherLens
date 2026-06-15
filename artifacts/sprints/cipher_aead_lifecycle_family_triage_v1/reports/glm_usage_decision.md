# GLM Usage Decision

```yaml
glm_used: false
must_not_generate_free_form_c: true
```

This sprint is family triage and B-path mutation planning. GLM should be used
later only if A-path recipe-slot migration is selected, and then only for strict
`slot_bindings`, not free-form C blocks.
