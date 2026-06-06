import argparse
from pathlib import Path
from template_maker import ast_mask_lite


def run_lite_backend(root: Path, output_name: str) -> int:
    if not root.exists():
        raise FileNotFoundError(f"root not found: {root}")

    count = 0
    for template_dir in ast_mask_lite.find_template_dirs(root):
        report = ast_mask_lite.build_report(template_dir)
        report.setdefault("summary", {})
        report["summary"]["backend"] = "lite"
        out_path = template_dir / output_name
        ast_mask_lite.dump_yaml(out_path, report)
        print(f"[OK] wrote {out_path} units={len(report.get('ast_mask_units', []))}")
        count += 1

    print("=" * 80)
    print(f"[SUMMARY] backend: lite")
    print(f"[SUMMARY] template dirs scanned: {count}")
    print(f"[SUMMARY] root: {root}")
    return count


def run_tree_sitter_backend(root: Path, output_name: str) -> int:
    try:
        from template_maker import ast_mask_tree_sitter
    except ImportError as e:
        raise RuntimeError(
            "tree-sitter AST backend is not available yet. "
            "Add template_maker/ast_mask_tree_sitter.py and install optional "
            "tree_sitter/tree_sitter_c dependencies, or run with --backend lite."
        ) from e

    if not hasattr(ast_mask_tree_sitter, "run"):
        raise RuntimeError(
            "template_maker.ast_mask_tree_sitter must expose run(root: Path, output_name: str)."
        )

    return int(ast_mask_tree_sitter.run(root, output_name))


def default_output_name(backend: str) -> str:
    if backend == "lite":
        return "ast_mask_report.yaml"
    return f"ast_mask_report.{backend.replace('-', '_')}.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate AST mask reports using a selectable backend."
    )
    parser.add_argument("--root", default="normalized_templates")
    parser.add_argument(
        "--backend",
        default="lite",
        choices=["lite", "tree-sitter"],
        help="AST backend to use. The lite backend preserves current behavior.",
    )
    parser.add_argument(
        "--output-name",
        help=(
            "Output YAML filename inside each template directory. Defaults to "
            "ast_mask_report.yaml for lite and backend-qualified names otherwise."
        ),
    )
    args = parser.parse_args()

    root = Path(args.root)
    output_name = args.output_name or default_output_name(args.backend)

    if args.backend == "lite":
        run_lite_backend(root, output_name)
        return 0

    if args.backend == "tree-sitter":
        try:
            run_tree_sitter_backend(root, output_name)
            return 0
        except RuntimeError as e:
            print(f"[ERROR] {e}")
            return 1

    parser.error(f"unknown backend: {args.backend}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
