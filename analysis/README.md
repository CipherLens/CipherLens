# analysis/ Directory Guide

`analysis/` is now scoped to the current mainline dependency closure: core reusable modules, GLM helpers, oracle modules, and the single core automation entrypoint.

## Unique Core Entrypoint

- `analysis/full_mainline_glm_oracle_campaign.py`

This is the only core automation root for the current mainline. It must keep running with:

```bash
PYTHONPATH=. python3 analysis/full_mainline_glm_oracle_campaign.py \
  --repo-root . \
  --out-dir artifacts/cross_library/mainline/one_click_full_mainline_glm_oracle_campaign_v1 \
  --targets mbedtls-3.6.4-asan,mbedtls-4.1.0-asan,botan-3.10.0-asan \
  --families pkey_sign_verify,mac_digest_lifecycle,aead_lifecycle,roundtrip,parser_full_consumption \
  --seed-source mixed \
  --execution-mode syntax_only \
  --oracle-mode dispatch \
  --max-families 5 \
  --max-cases 60 \
  --max-compile-jobs 80 \
  --probe-mode existing
```

## Recommended User Entrypoints

- `tools/mainline/run_one_click_glm_oracle_campaign.py`
- `tools/mainline/run_multi_target_family_campaign.py`

New runner scripts must not be added to `analysis/` or the `tools/` root. Put thin user-facing wrappers under `tools/mainline/`.

## Framework Map

Current framework and automation file maps are recorded under:

```text
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/framework_tree.md
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/automation_involved_files.yaml
artifacts/cross_library/mainline/root_runner_dependency_cleanup_v1/next_delete_review_table.md
```

Before deleting any remaining old `analysis/*.py` file, check both `automation_involved_files.yaml` and `next_delete_review_table.md`. Some files are not direct imports from the root runner but are kept as `protected_mainline`, `oracle_module`, or `family_oracle` support.

## Scratch Policy

Temporary scan/audit/cleanup helpers must live under:

```text
artifacts/cross_library/mainline/<task>/scratch/
```

Old scripts outside the root dependency closure are treated as historical campaign or one-off code and are removed from the active tree when explicitly requested. Git history remains the recovery path.

## Deleted Legacy Script Patches

The old `analysis/*.py` scripts marked `delete_after_user_confirm` were removed from the active tree after saving local modification patches under:

```text
artifacts/cross_library/mainline/delete_review_pending_analysis_legacy_v1/deleted_patches/
```

Tracked deleted files can also be recovered from Git history. Do not reintroduce old runners into `analysis/`; use `tools/mainline/` for thin wrappers.
