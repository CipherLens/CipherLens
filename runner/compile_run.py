import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from utils.path_resolver import resolve_path_config


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "runner_config.yaml"


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def detect_library(path: Path) -> str:
    name = path.name.lower()
    if name.endswith("_openssl.c") or name.endswith("_openssl.cpp") or name == "default_openssl.c":
        return "openssl"
    if name.endswith("_mbedtls.c") or name.endswith("_mbedtls.cpp") or name == "default_mbedtls.c":
        return "mbedtls"
    if name.endswith("_botan.c") or name.endswith("_botan.cpp") or name == "default_botan.c":
        return "botan"

    # Fallback is intentionally limited to the filename. Artifact roots may
    # contain strings such as "mbedtls-poc" even for OpenSSL target cases.
    if "openssl" in name:
        return "openssl"
    if "mbedtls" in name:
        return "mbedtls"
    if "botan" in name:
        return "botan"
    return "unknown"


def is_cpp_file(path: Path) -> bool:
    return path.suffix.lower() in {".cpp", ".cc", ".cxx"}


def shell_join(cmd: List[str]) -> str:
    return " ".join(shlex.quote(x) for x in cmd)


def build_compile_command(
    source_file: Path,
    output_bin: Path,
    cfg: Dict[str, Any],
    library: str,
) -> List[str]:
    compiler_cfg = cfg.get("compiler", {})
    lib_cfg = cfg.get("libraries", {}).get(library, {})

    compiler = compiler_cfg.get("cxx" if is_cpp_file(source_file) else "cc", "clang")
    flags = compiler_cfg.get("common_flags", [])
    lib_dirs = lib_cfg.get("lib_dirs", []) or lib_cfg.get("library_dirs", [])
    rpath_dirs = lib_cfg.get("rpath_dirs", lib_dirs)

    cmd = [compiler]
    cmd.extend(flags)

    for inc in lib_cfg.get("include_dirs", []):
        cmd.append(f"-I{inc}")

    cmd.append(str(source_file))
    cmd.extend(["-o", str(output_bin)])

    for lib_dir in lib_dirs:
        cmd.append(f"-L{lib_dir}")

    # rpath lets the executable find locally built shared libraries.
    for lib_dir in rpath_dirs:
        cmd.append(f"-Wl,-rpath,{lib_dir}")

    for lib in lib_cfg.get("libs", []):
        cmd.append(f"-l{lib}")

    return cmd


def run_subprocess(
    cmd: List[str],
    timeout: int,
    env_extra: Dict[str, str] | None = None,
) -> Tuple[int | None, str, str, bool]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=env,
        )
        return p.returncode, p.stdout, p.stderr, False
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or "", e.stderr or "", True


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def collect_sources(input_root: Path) -> List[Path]:
    files = []
    files.extend(input_root.rglob("*.c"))
    files.extend(input_root.rglob("*.cpp"))
    files.extend(input_root.rglob("*.cc"))
    files.extend(input_root.rglob("*.cxx"))
    return sorted(files)


def truncate_text(s: str, limit: int = 12000) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n...[truncated {len(s) - limit} chars]..."


def find_nearest_file(start: Path, stop: Path, filename: str) -> Optional[Path]:
    current = start.resolve()
    stop = stop.resolve()

    while True:
        candidate = current / filename
        if candidate.exists():
            return candidate
        if current == stop or stop not in current.parents:
            return None
        current = current.parent


def load_yaml_if_exists(path: Optional[Path]) -> Dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        return load_yaml(path)
    except Exception as e:
        return {"_load_error": str(e)}


def infer_target_from_cross_mapping(cross_mapping: Dict[str, Any], library: str) -> Dict[str, str]:
    target = cross_mapping.get("target", {}) if isinstance(cross_mapping.get("target"), dict) else {}
    if target:
        return {
            "target_library": str(target.get("library") or library or ""),
            "target_api": str(target.get("candidate_api") or target.get("api") or ""),
        }
    return {"target_library": library or "", "target_api": ""}


def infer_target_from_template_meta(template_meta: Dict[str, Any], library: str) -> Dict[str, str]:
    cross_library = template_meta.get("cross_library", {})
    if isinstance(cross_library, dict):
        if library in cross_library and isinstance(cross_library[library], dict):
            return {
                "target_library": library,
                "target_api": str(cross_library[library].get("target_api") or ""),
            }
        for lib, meta in cross_library.items():
            if isinstance(meta, dict):
                return {
                    "target_library": str(lib),
                    "target_api": str(meta.get("target_api") or ""),
                }
    return {"target_library": library or "", "target_api": ""}


def compact_ast_mask_selection(template_meta: Dict[str, Any], cross_mapping: Dict[str, Any], adapter_meta: Dict[str, Any]) -> Dict[str, Any]:
    for obj in (template_meta, cross_mapping, adapter_meta):
        if not isinstance(obj, dict):
            continue
        value = obj.get("ast_mask_selection") or obj.get("ast_mask_selection_trace")
        if isinstance(value, dict):
            return value
    return {}


def load_case_metadata(src: Path, input_root: Path, library: str) -> Dict[str, Any]:
    template_meta_path = find_nearest_file(src.parent, input_root, "template_meta.yaml")
    cross_mapping_path = find_nearest_file(src.parent, input_root, "cross_mapping.yaml")
    adapter_meta_path = find_nearest_file(src.parent, input_root, "adapter_meta.yaml")

    template_meta = load_yaml_if_exists(template_meta_path)
    cross_mapping = load_yaml_if_exists(cross_mapping_path)
    adapter_meta = load_yaml_if_exists(adapter_meta_path)

    target_from_mapping = infer_target_from_cross_mapping(cross_mapping, library)
    target_from_meta = infer_target_from_template_meta(template_meta, library)
    source_from_mapping = cross_mapping.get("source", {}) if isinstance(cross_mapping.get("source"), dict) else {}
    poc_source = template_meta.get("poc_source", {}) if isinstance(template_meta.get("poc_source"), dict) else {}

    target_library = target_from_mapping.get("target_library") or target_from_meta.get("target_library") or library
    target_api = target_from_mapping.get("target_api") or target_from_meta.get("target_api")

    return {
        "template": {
            "template_id": template_meta.get("template_id") or source_from_mapping.get("template_id") or "",
            "source_template_id": template_meta.get("source_template_id") or "",
            "harness_family": template_meta.get("harness_family") or cross_mapping.get("harness_family") or "",
            "oracle_type": template_meta.get("oracle_type") or cross_mapping.get("oracle_type") or "",
            "source_library": poc_source.get("library") or source_from_mapping.get("library") or template_meta.get("source_library", ""),
            "source_api": poc_source.get("api") or source_from_mapping.get("api") or template_meta.get("source_api", ""),
            "target_library": target_library or "",
            "target_api": target_api or "",
        },
        "metadata_files": {
            "template_meta": str(template_meta_path) if template_meta_path else "",
            "cross_mapping": str(cross_mapping_path) if cross_mapping_path else "",
            "adapter_meta": str(adapter_meta_path) if adapter_meta_path else "",
        },
        "ast_mask_selection": compact_ast_mask_selection(template_meta, cross_mapping, adapter_meta),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile and run rendered C/C++ harnesses.")
    parser.add_argument("--input-root", default="rendered_cases", help="Rendered cases root.")
    parser.add_argument("--build-root", default="runner/build", help="Build output root.")
    parser.add_argument("--result", default="runner/results/run_default.jsonl", help="Result jsonl path.")
    parser.add_argument("--dry-run", action="store_true", help="Only print compile commands.")
    parser.add_argument("--keep-going", action="store_true", help="Continue after compile/run failures.")
    args = parser.parse_args()

    cfg = resolve_path_config(load_yaml(CONFIG_PATH))

    input_root = Path(args.input_root)
    build_root = Path(args.build_root)
    result_path = Path(args.result)

    if not input_root.exists():
        print(f"[ERROR] input root not found: {input_root}")
        return 1

    sources = collect_sources(input_root)
    if not sources:
        print(f"[ERROR] no C/C++ source found under {input_root}")
        return 1

    ensure_parent(result_path)

    runtime_cfg = cfg.get("runtime", {})
    timeout = int(runtime_cfg.get("timeout_seconds", 20))
    env_extra = runtime_cfg.get("env", {})

    print(f"[INFO] sources: {len(sources)}")
    print(f"[INFO] result: {result_path}")

    with result_path.open("w", encoding="utf-8") as out:
        for src in sources:
            rel = src.relative_to(input_root)
            library = detect_library(src)

            bin_name = rel.with_suffix("")
            output_bin = build_root / bin_name
            ensure_parent(output_bin)

            compile_cmd = build_compile_command(src, output_bin, cfg, library)
            case_metadata = load_case_metadata(src, input_root, library)

            record: Dict[str, Any] = {
                "source": str(src),
                "relative_source": str(rel),
                "library": library,
                "template": case_metadata["template"],
                "metadata_files": case_metadata["metadata_files"],
                "ast_mask_selection": case_metadata["ast_mask_selection"],
                "binary": str(output_bin),
                "compile_cmd": compile_cmd,
                "compile_cmd_str": shell_join(compile_cmd),
                "compile": {},
                "run": {},
                "status": "",
            }

            print("=" * 100)
            print(f"[CASE] {src}")
            print(f"[LIB]  {library}")
            if record["template"].get("template_id"):
                print(
                    f"[META] template={record['template'].get('template_id')} "
                    f"family={record['template'].get('harness_family')} "
                    f"target={record['template'].get('target_library')}.{record['template'].get('target_api')}"
                )
            print(f"[CMD]  {record['compile_cmd_str']}")

            if args.dry_run:
                record["status"] = "dry_run"
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                continue

            code, stdout, stderr, timed_out = run_subprocess(
                compile_cmd,
                timeout=timeout,
                env_extra=env_extra,
            )

            record["compile"] = {
                "returncode": code,
                "timeout": timed_out,
                "stdout": truncate_text(stdout),
                "stderr": truncate_text(stderr),
            }

            if timed_out or code != 0:
                record["status"] = "compile_error"
                print("[COMPILE] failed")
                print(stderr[-2000:])
                out.write(json.dumps(record, ensure_ascii=False) + "\n")
                if not args.keep_going:
                    return 1
                continue

            print("[COMPILE] ok")

            run_cmd = [str(output_bin)]
            code, stdout, stderr, timed_out = run_subprocess(
                run_cmd,
                timeout=timeout,
                env_extra=env_extra,
            )

            record["run"] = {
                "returncode": code,
                "timeout": timed_out,
                "stdout": truncate_text(stdout),
                "stderr": truncate_text(stderr),
            }

            if timed_out:
                record["status"] = "run_timeout"
                print("[RUN] timeout")
            elif code == 0:
                record["status"] = "run_ok"
                print("[RUN] ok")
            else:
                record["status"] = "run_nonzero"
                print(f"[RUN] nonzero exit: {code}")

            print(stdout[-2000:])
            if stderr:
                print(stderr[-2000:])

            out.write(json.dumps(record, ensure_ascii=False) + "\n")

    print("=" * 100)
    print(f"[SUMMARY] done. results written to {result_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
