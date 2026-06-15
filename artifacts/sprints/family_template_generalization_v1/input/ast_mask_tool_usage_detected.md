# AST mask tool usage detected

- `template_maker/ast_mask_tree_sitter.py` is the backend module; direct `--help` produced no CLI help.
- The usable CLI wrapper is `python3 -m template_maker.ast_mask --backend tree-sitter`.
- It can write `ast_mask_report.yaml` when called with `--output-name ast_mask_report.yaml`.
- `template_maker/ast_mask_select.py` can read `ast_mask_report.yaml` and write `selected_mask_units.yaml`.
- Fallback to `lite` is needed if optional tree-sitter dependencies or backend invocation fail.
