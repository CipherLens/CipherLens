# Candidate Queue

This directory is a triage layer between the unified pattern bank and runnable migration sprints.

`readiness_score` estimates whether a candidate has enough evidence, oracle clarity, RAG recall, and reusable rendering support to run now.
`severity_score` estimates the potential security impact. The two are intentionally separate so crash-heavy but poorly grounded cases do not automatically outrank runnable semantic candidates.
