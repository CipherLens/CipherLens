# Tools Policy

`tools/` is reserved for thin CLI wrappers and sprint orchestration.

Do not add new core business logic to `tools/`.

## Allowed In Tools

- Thin CLI wrappers around package modules.
- Sprint orchestration scripts that glue existing modules together.
- Read-only inventory/report entrypoints.
- Backward-compatible entrypoints used by existing local commands.

## Not Allowed In Tools

- Core compile/run/sanitizer logic.
- Core oracle-event parsing or semantic labeling.
- Core mutation planning or mutation policy.
- Core render planning, case rendering, or oracle instrumentation.
- Core runtime feedback, candidate queue, scheduler proposal, or closure logic.
- New feature implementations that should belong to `runner/`, `analyzer/`,
  `mutation/`, `template_maker/`, or `analysis/`.

## Where New Logic Goes

```text
runner/
  compile/run/sanitizer

analyzer/
  oracle event / semantic label / candidate label

mutation/
  mutation planning / valid-prefix refinement

template_maker/
  render plan / render cases / oracle instrumentation

analysis/
  feedback / candidate queue / scheduler proposal / closure report
```

## Artifact Rule

`artifacts/` stores outputs only.

Sprint artifacts are not core code. They may describe decisions, smoke results,
and handoff records, but reusable logic belongs in package modules.

## Cleanup Rule

Legacy `tools/*.py` files can be deleted only when:

1. Active references are zero.
2. A replacement package module exists.
3. The file is not a recommended CLI wrapper or pipeline orchestrator.
4. A delete decision artifact records the reason.
5. Validation passes.

When in doubt, keep a thin wrapper and move the core logic out.
