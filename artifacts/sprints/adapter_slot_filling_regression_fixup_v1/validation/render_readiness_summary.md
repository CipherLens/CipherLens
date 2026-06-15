# Render Readiness Summary

```yaml
schema: render_readiness_summary_v1
render_ready_adapters:
- adapter_id: pkcs_container_parsing_openssl
  family: pkcs_container_parsing
  target_library: openssl
  reason: validation pass; render may be planned next but not run in this sprint
- adapter_id: asn1_nested_boundary_openssl
  family: asn1_nested_boundary
  target_library: openssl
  reason: validation pass; render may be planned next but not run in this sprint
blocked_adapters:
- adapter_id: asn1_nested_boundary_mbedtls
  family: asn1_nested_boundary
  target_library: mbedtls
  reason: blocked placeholder preserved; render_ready=false
not_ready_adapters: []
summary:
  pass: 2
  blocked_expected: 1
  fail: 0
  render_ready_count: 2
```
