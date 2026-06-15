# Project Structure

This repository is still located at:

```text
~/work/crypto-pattern-fuzz
```

The project is an academic research prototype for cryptographic-library
vulnerability-pattern migration. It is not an AFL++ coverage-guided fuzzing
project, and it should not become a direct LLM-to-C harness generation demo.

## Directory Responsibilities

```text
runner/
  Compile/run/sanitizer execution support.
  Owns execution records, sanitizer environment setup, and family compile/run helpers.

analyzer/
  Oracle event parsing, semantic labels, candidate labels, and oracle-aware analysis.
  Owns interpretation of existing runtime artifacts, not execution.

mutation/
  Mutation planning, valid-prefix refinement, mutation policy, and mutation case records.
  Owns family-level mutation space and planning artifacts.

template_maker/
  Render planning, render cases, template rendering, and oracle instrumentation helpers.
  Owns target harness rendering mechanics and render metadata.

analysis/
  Runtime feedback, candidate queue, scheduler proposal, family-loop closure, and reports.
  Owns read-only synthesis and staged feedback artifacts.

tools/
  Thin CLI wrappers and sprint pipeline orchestration only.
  Core business logic should not be added here.

artifacts/
  Generated outputs only.
  Sprint artifacts are evidence and handoff records, not core code.
```

## Placement Rule

New reusable logic should go into the owning package:

- `runner/` for compile, run, sanitizer, and execution records.
- `analyzer/` for oracle events, semantic classification, and candidate labels.
- `mutation/` for mutation planning and mutation policy.
- `template_maker/` for render planning, rendering, and oracle instrumentation.
- `analysis/` for feedback, queues, scheduler proposals, and closure reports.

Use `tools/` only when a stable command-line entrypoint or sprint orchestrator is
needed. If a `tools/*.py` file grows reusable logic, move that logic into the
appropriate package and keep `tools/` as a wrapper.

## Deletion Rule

Old scripts may be removed only after all of the following are true:

1. Active references are zero.
2. A replacement module exists.
3. The old file is not a recommended CLI entrypoint.
4. The deletion decision is recorded in a sprint artifact.
5. The relevant smoke/validation checks pass.

Historical artifact references may be recorded separately and do not by
themselves block cleanup.
