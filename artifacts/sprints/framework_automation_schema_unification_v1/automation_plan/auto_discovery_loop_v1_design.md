# auto_discovery_loop_v1 Design

The discovery loop is staged so the framework learns to schedule and triage before it is allowed to render or run anything.

```yaml
schema_version: 1
component: auto_discovery_loop_v1
phases:
  phase_1:
    name: auto scheduler only
    render_run_allowed: false
    claim_allowed: false
  phase_2:
    name: auto triage
    render_run_allowed: false
    claim_allowed: false
  phase_3:
    name: gated render/run
    render_run_allowed: only_if_evidence_gate_passes
    claim_allowed: false
  phase_4:
    name: high-value candidate extraction
    render_run_allowed: bounded
    claim_allowed: minimal_reproducer_handoff_only
stop_conditions:
- normal control failed
- seed missing
- placeholder only
- RAG evidence insufficient
- API mapping gap
- compile errors above threshold
- too many needs_triage
- negative feedback repeated
safety_policy:
- no confirmed vulnerability claim
- no CVE claim
- no exploitability claim
- no free-form C generation
- no fuzzing by default
```
