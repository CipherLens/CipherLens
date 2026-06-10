# Crash/Sanitizer Audit

This directory records a read-only evidence audit for the crash/sanitizer top5
from `artifacts/candidate_queue/candidate_queue.yaml`.

The audit does not claim any new vulnerability. It checks local artifact
presence, crash/sanitizer signatures, repro commands, version information,
harness misuse risk, and migration readiness before recommending a runnable
family.

Recommended next family: `secure_heap_state_lifecycle`
Seed issue: `OPENSSL-ISSUE-28669`
Start runnable sprint now: `true`
