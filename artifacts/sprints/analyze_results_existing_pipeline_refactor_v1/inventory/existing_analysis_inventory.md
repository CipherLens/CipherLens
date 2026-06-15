# Existing Analysis Inventory

- analyzer/analyze_poc.py: lightweight C PoC structure extractor: includes, macros, API calls, trigger call, oracle helper names, library guess
- runner/analyze_results.py: existing verdict classifier for compile/run records, sanitizer text, BUG/OK oracle strings, and family-aware semantic verdicts
- analysis/audit_crash_sanitizer_candidates.py: candidate queue crash/sanitizer evidence audit with signature flags and promotion readiness scoring
- analysis/build_candidate_queue.py: pattern-bank to candidate-queue readiness/severity/candidate class scoring
- analysis/plan_execution_paths.py: route candidate families into execution paths A/B/C/D based on family/oracle/readiness
