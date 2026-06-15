# Runner Inventory

- runner files: `17`
- poc-level legacy runner: `runner/compile_run.py, runner/analyze_results.py, runner/analyze_cross_results.py, runner/render_repair_prompt.py, runner/build_repair_queue.py`
- reusable logic: existing `runner/compile_run.py`; new `runner/sanitizer_env.py`, `runner/run_records.py`, `runner/family_compile_runner.py`
- conflict risk: low; new module names did not preexist and old runner files were not overwritten
