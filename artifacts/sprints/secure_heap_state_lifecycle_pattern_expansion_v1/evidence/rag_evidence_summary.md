# RAG Evidence Summary

RAG was attempted in the sandbox first and failed because local Ollama embedding returned `Operation not permitted`. The queries were then rerun with approved escalation and completed successfully.

## Recall

- `secure_heap_state_lifecycle`: recalled.
- `OPENSSL-ISSUE-28669`: recalled.
- API contract / version novelty: recalled through pattern notes and prior qualification material.
- Same-family API expansion: supported as evidence.
- Cross-version matrix: supported as a planned evidence path.

## Boundary

RAG is used only as evidence. It does not prove a vulnerability, CVE, or affected-version range. The final interpretation still depends on source inspection, case manifests, crash evidence, controls, and version classification.
