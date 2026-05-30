import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

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

            record: Dict[str, Any] = {
                "source": str(src),
                "relative_source": str(rel),
                "library": library,
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
