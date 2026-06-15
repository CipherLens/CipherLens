# Framework Automation Schema Unification Report

## Why Stop Manual Family Push
The project has enough representative outcomes to encode scheduler behavior: A-path recipe-slot migration, B-path controlled mutation, C-path app validation gap, D-path evidence audit, external validation, negative feedback, and seed-missing block. Another manual family would add less leverage than unifying the gates and feedback structures.

## Existing Family Coverage
| family | route | outcome | claim_level |
| --- | --- | --- | --- |
| mac_lifecycle | A_recipe_slot_cross_library_migration | migrated_safe | needs_triage |
| der_full_consumption | C_app_level_validation_gap | app_level_validation_gap_candidate | semantic_divergence_candidate |
| secure_heap_state_lifecycle | B_controlled_family_mutation | validated_new_state_candidate | validated_new_state_candidate |
| cipher_aead_lifecycle | B_controlled_family_mutation | negative_feedback | no_claim |
| asn1_nested_boundary | blocked_seed_missing | blocked_seed_missing | no_claim |

## Why Schema Unification
The framework needs stable contracts for family profiles, route decisions, RAG evidence strength, API mapping readiness, mutation/render plans, analyzer labels, feedback rows, and scheduler scoring. Without those contracts, each family stays hand-driven.

## RAG Accuracy
RAG evidence is gated by source priority and strength. Official docs, source code, and official tests outrank issue metadata and prior artifacts. Weak or ambiguous evidence blocks auto-render.

## GLM Limits
GLM is allowed only for A-path strict recipe-slot filling after the A-path gate passes. It cannot generate free-form C, guess API contracts, interpret sanitizer logs, or make vulnerability claims.

## Legal Semantics False Positives
AEAD-GCM shows why permissive behavior must be cross-checked. Empty plaintext GCM and allowed truncated tags become negative feedback, not vulnerability candidates.

## Seed Missing
ASN.1 issue_30581 shows the block rule: placeholder-only input or missing real seed prevents D-path reproduction, crash claims, A-path escalation, and auto-render.

## Scheduler Scoring
Scores combine seed quality, oracle clarity, API mapping clarity, mutation quality, prior positive signal, novelty, execution cost, negative feedback, seed-missing penalty, and external validation penalty.

## auto_scheduler_v1
The next task should read pattern bank, scheduler seed, feedback JSONL, and PoC pattern notes, then emit family rerank, route decision, evidence gate result, next task, GLM allowance, and auto render/run allowance.

## auto_discovery_loop_v1
The loop should proceed in four phases: scheduler only, auto triage, gated render/run, and high-value candidate handoff.

## Claim Boundary
No vulnerability, CVE, exploitability, or crash was discovered or claimed in this sprint.

## Next Task
`auto_scheduler_v1`
