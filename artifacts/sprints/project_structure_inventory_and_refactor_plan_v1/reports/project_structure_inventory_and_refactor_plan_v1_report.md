# Project Structure Inventory And Refactor Plan v1

- `tools/` overloaded with core logic: true.
- Move mutation logic to `mutation/`.
- Move compile/run logic to `runner/`.
- Move oracle parsing and semantic labels to `analyzer/`.
- Move feedback, queues, audits, and reports to `analysis/`.
- Move render/template logic to `template_maker/`.
- Keep `tools/` as thin CLI/sprint wrappers.
- Safe to delete now: false.
- Current loop type: sprint-driven manual orchestration.
- Next task: `project_structure_refactor_phase1_runner_v1`.
