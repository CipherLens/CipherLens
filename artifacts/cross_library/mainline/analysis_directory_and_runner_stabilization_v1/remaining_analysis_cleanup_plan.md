# Remaining Analysis Cleanup Plan

Do not move or delete formal scripts in this pass. Keep `cat_*.py`, `cross_library_*.py`, `crypto_*.py`, `family_*.py`, and `campaign_*.py` in place until imports and artifact references are audited.

Recommended next steps:

1. Keep `analysis/README.md`, `analysis/mainline_entrypoints.yaml`, and `analysis/script_inventory.yaml` as the directory guide.
2. For future Codex tasks, create temporary helper scripts under `artifacts/cross_library/mainline/<task>/scratch/`.
3. Review `unknown_need_review` entries in `analysis/script_inventory.yaml` before any future archive/move operation.
4. Do not delete tracked files without an explicit migration plan.
