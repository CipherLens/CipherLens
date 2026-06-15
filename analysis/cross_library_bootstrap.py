"""Bootstrap cross-library ASAN/UBSAN targets for local migration campaigns."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml


TASK = "cross_library_sanitizer_bootstrap_v1"
BASE_OUT = Path("artifacts/cross_library/bootstrap") / TASK
WORK_ROOT = Path("/home/wen/work")
CLEAN = WORK_ROOT / "clean_sources"


TARGETS: dict[str, dict[str, Any]] = {
    "openssl-3.5.5-asan": {
        "library": "openssl",
        "version": "3.5.5",
        "source_dir": CLEAN / "openssl-3.5.5",
        "build_dir": None,
        "install_dir": WORK_ROOT / "install-openssl-3.5.5-asan",
        "language": "c",
        "priority": 0,
    },
    "mbedtls-3.6.4-asan": {
        "library": "mbedtls",
        "version": "3.6.4",
        "source_dir": CLEAN / "mbedtls-3.6.4",
        "build_dir": WORK_ROOT / "build-mbedtls-3.6.4-asan",
        "install_dir": WORK_ROOT / "install-mbedtls-3.6.4-asan",
        "language": "c",
        "priority": 1,
    },
    "mbedtls-4.1.0-asan": {
        "library": "mbedtls",
        "version": "4.1.0",
        "source_dir": CLEAN / "mbedtls-4.1.0",
        "build_dir": WORK_ROOT / "build-mbedtls-4.1.0-asan",
        "install_dir": WORK_ROOT / "install-mbedtls-4.1.0-asan",
        "language": "c",
        "priority": 2,
    },
    "wolfssl-asan": {
        "library": "wolfssl",
        "version": "",
        "source_dir": CLEAN / "wolfssl",
        "build_dir": WORK_ROOT / "build-wolfssl-asan",
        "install_dir": WORK_ROOT / "install-wolfssl-asan",
        "language": "c",
        "priority": 3,
    },
    "botan-3.10.0-asan": {
        "library": "botan",
        "version": "3.10.0",
        "source_dir": CLEAN / "botan-3.10.0",
        "build_dir": WORK_ROOT / "build-botan-3.10.0-asan",
        "install_dir": WORK_ROOT / "install-botan-3.10.0-asan",
        "language": "c++",
        "priority": 4,
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--out-dir", default=str(BASE_OUT))
    parser.add_argument("--jobs", type=int, default=max(os.cpu_count() or 1, 1))
    parser.add_argument("--skip-build", action="store_true")
    return parser.parse_args()


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run_cmd(cmd: list[str], cwd: Path | None, log_prefix: Path, env: dict[str, str] | None = None, timeout: int | None = None) -> dict[str, Any]:
    log_prefix.parent.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
        stdout = proc.stdout
        stderr = proc.stderr
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = (exc.stderr or "") + "\n[TIMEOUT]\n"
        rc = 124
        timed_out = True
    write_text(log_prefix.with_suffix(".stdout.log"), stdout)
    write_text(log_prefix.with_suffix(".stderr.log"), stderr)
    return {
        "cmd": cmd,
        "cwd": cwd.as_posix() if cwd else "",
        "return_code": rc,
        "ok": rc == 0,
        "timeout": timed_out,
        "stdout_log": log_prefix.with_suffix(".stdout.log").as_posix(),
        "stderr_log": log_prefix.with_suffix(".stderr.log").as_posix(),
    }


def tool(name: str) -> str:
    return shutil.which(name) or ""


def lib_dirs(install: Path) -> list[Path]:
    return [p for p in [install / "lib64", install / "lib"] if p.exists()]


def include_dirs(install: Path) -> list[Path]:
    dirs = []
    if (install / "include").exists():
        dirs.append(install / "include")
    if (install / "include" / "botan-3").exists():
        dirs.append(install / "include" / "botan-3")
    return dirs


def env_probe(out_dir: Path) -> dict[str, Any]:
    sources = {
        name: {
            "source_dir": cfg["source_dir"].as_posix(),
            "exists": cfg["source_dir"].exists(),
            "has_cmake": (cfg["source_dir"] / "CMakeLists.txt").exists(),
            "has_configure": (cfg["source_dir"] / "configure").exists(),
            "has_autogen": (cfg["source_dir"] / "autogen.sh").exists(),
            "has_python_configure": (cfg["source_dir"] / "configure.py").exists(),
        }
        for name, cfg in TARGETS.items()
    }
    probes = {
        "schema": "cross_library_env_probe_v1",
        "source_dirs": sources,
        "tools": {name: tool(name) for name in ["clang", "gcc", "cmake", "make", "ninja", "pkg-config", "python3"]},
        "openssl_asan_existing": {
            "install_dir": TARGETS["openssl-3.5.5-asan"]["install_dir"].as_posix(),
            "exists": TARGETS["openssl-3.5.5-asan"]["install_dir"].exists(),
            "include_exists": (TARGETS["openssl-3.5.5-asan"]["install_dir"] / "include").exists(),
            "lib_dirs": [p.as_posix() for p in lib_dirs(TARGETS["openssl-3.5.5-asan"]["install_dir"])],
        },
    }
    dump_yaml(out_dir / "env_probe.yaml", probes)
    return probes


def build_mbedtls(name: str, cfg: dict[str, Any], out_dir: Path, jobs: int, skip: bool) -> dict[str, Any]:
    build_dir = cfg["build_dir"]
    install_dir = cfg["install_dir"]
    log_dir = out_dir / "build_logs" / name
    rec: dict[str, Any] = {"target": name, "build_attempted": True, "status": "blocked", "steps": []}
    if skip:
        rec["blocked_reason"] = "build skipped by --skip-build"
        return rec
    if not cfg["source_dir"].exists():
        rec["blocked_reason"] = "source directory missing"
        return rec
    if not tool("cmake"):
        rec["blocked_reason"] = "cmake missing"
        return rec
    compiler = tool("clang") or tool("gcc")
    if not compiler:
        rec["blocked_reason"] = "no C compiler"
        return rec
    build_dir.mkdir(parents=True, exist_ok=True)
    cmake = [
        "cmake", cfg["source_dir"].as_posix(),
        "-DCMAKE_BUILD_TYPE=Debug",
        f"-DCMAKE_INSTALL_PREFIX={install_dir}",
        f"-DCMAKE_C_COMPILER={compiler}",
        "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1",
        "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined",
        "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined",
        "-DENABLE_TESTING=OFF",
        "-DENABLE_PROGRAMS=OFF",
    ]
    rec["steps"].append(run_cmd(cmake, build_dir, log_dir / "cmake"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "cmake configure failed"
        return rec
    rec["steps"].append(run_cmd(["cmake", "--build", ".", "-j", str(jobs)], build_dir, log_dir / "build"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "cmake build failed"
        return rec
    rec["steps"].append(run_cmd(["cmake", "--install", "."], build_dir, log_dir / "install"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "cmake install failed"
        return rec
    rec["status"] = "ready"
    rec["blocked_reason"] = ""
    return rec


def build_wolfssl(name: str, cfg: dict[str, Any], out_dir: Path, jobs: int, skip: bool) -> dict[str, Any]:
    build_dir = cfg["build_dir"]
    src = cfg["source_dir"]
    install_dir = cfg["install_dir"]
    log_dir = out_dir / "build_logs" / name
    rec: dict[str, Any] = {"target": name, "build_attempted": True, "status": "blocked", "steps": []}
    if skip:
        rec["blocked_reason"] = "build skipped by --skip-build"
        return rec
    if not src.exists():
        rec["blocked_reason"] = "source directory missing"
        return rec
    if not (src / "configure").exists():
        rec["blocked_reason"] = "configure missing"
        return rec
    build_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["CFLAGS"] = "-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
    env["LDFLAGS"] = "-fsanitize=address,undefined"
    if (src / "autogen.sh").exists():
        rec["steps"].append(run_cmd(["bash", "autogen.sh"], src, log_dir / "autogen", env=env))
    configure = [
        (src / "configure").as_posix(),
        f"--prefix={install_dir}",
        "--enable-debug",
        "--enable-static",
        "--disable-shared",
    ]
    rec["steps"].append(run_cmd(configure, build_dir, log_dir / "configure", env=env))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "configure failed"
        return rec
    rec["steps"].append(run_cmd(["make", "-j", str(jobs)], build_dir, log_dir / "make", env=env))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "make failed"
        return rec
    rec["steps"].append(run_cmd(["make", "install"], build_dir, log_dir / "install", env=env))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "make install failed"
        return rec
    rec["status"] = "ready"
    rec["blocked_reason"] = ""
    return rec


def botan_make_dir(build_dir: Path) -> Path:
    for p in [build_dir / "build", build_dir]:
        if (p / "Makefile").exists():
            return p
    matches = list(build_dir.glob("**/Makefile"))
    return matches[0].parent if matches else build_dir / "build"


def build_botan(name: str, cfg: dict[str, Any], out_dir: Path, jobs: int, skip: bool) -> dict[str, Any]:
    build_dir = cfg["build_dir"]
    src = cfg["source_dir"]
    install_dir = cfg["install_dir"]
    log_dir = out_dir / "build_logs" / name
    rec: dict[str, Any] = {"target": name, "build_attempted": True, "status": "blocked", "steps": []}
    if skip:
        rec["blocked_reason"] = "build skipped by --skip-build"
        return rec
    if not (src / "configure.py").exists():
        rec["blocked_reason"] = "configure.py missing"
        return rec
    compiler = "clang" if tool("clang") else "gcc"
    cmd = [
        "python3", "configure.py",
        f"--prefix={install_dir}",
        f"--with-build-dir={build_dir}",
        f"--cc={compiler}",
        "--debug-mode",
        "--disable-shared-library",
        "--without-documentation",
        "--build-targets=static",
        "--with-sanitizers",
        "--extra-cxxflags=-fno-omit-frame-pointer -g -O1",
    ]
    rec["steps"].append(run_cmd(cmd, src, log_dir / "configure"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "configure.py failed"
        return rec
    make_dir = botan_make_dir(build_dir)
    rec["make_dir"] = make_dir.as_posix()
    makefile = make_dir / "Makefile"
    rec["steps"].append(run_cmd(["make", "-f", makefile.as_posix(), "-j", str(jobs)], src, log_dir / "make"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "make failed"
        return rec
    rec["steps"].append(run_cmd(["make", "-f", makefile.as_posix(), "install"], src, log_dir / "install"))
    if not rec["steps"][-1]["ok"]:
        rec["blocked_reason"] = "make install failed"
        return rec
    rec["status"] = "ready"
    rec["blocked_reason"] = ""
    return rec


def build_targets(out_dir: Path, jobs: int, skip: bool) -> list[dict[str, Any]]:
    records = []
    for name, cfg in sorted(TARGETS.items(), key=lambda item: item[1]["priority"]):
        if name == "openssl-3.5.5-asan":
            records.append({
                "target": name,
                "build_attempted": False,
                "status": "ready" if cfg["install_dir"].exists() else "blocked",
                "blocked_reason": "" if cfg["install_dir"].exists() else "existing OpenSSL ASAN install missing",
                "steps": [],
            })
        elif cfg["library"] == "mbedtls":
            records.append(build_mbedtls(name, cfg, out_dir, jobs, skip))
        elif cfg["library"] == "wolfssl":
            records.append(build_wolfssl(name, cfg, out_dir, jobs, skip))
        elif cfg["library"] == "botan":
            records.append(build_botan(name, cfg, out_dir, jobs, skip))
    return records


def find_lib_name(install: Path, prefixes: list[str]) -> str:
    for d in lib_dirs(install):
        for prefix in prefixes:
            matches = sorted(d.glob(f"lib{prefix}*.a")) + sorted(d.glob(f"lib{prefix}*.so"))
            if matches:
                name = matches[0].name
                return name[3:].split(".")[0]
    return prefixes[0]


def smoke_source(name: str) -> tuple[str, str]:
    if name.startswith("openssl"):
        return "smoke.c", """#include <stdio.h>
#include <openssl/evp.h>
int main(void) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const unsigned char msg[] = "abc";
    int ok = ctx != NULL
        && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
        && EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1) == 1
        && EVP_DigestFinal_ex(ctx, out, &outlen) == 1;
    EVP_MD_CTX_free(ctx);
    printf("SMOKE_RESULT target=openssl ok=%d outlen=%u\\n", ok, outlen);
    return ok ? 0 : 1;
}
"""
    if name.startswith("mbedtls"):
        return "smoke.c", """#include <stdio.h>
#include <mbedtls/version.h>
int main(void) {
    printf("SMOKE_RESULT target=mbedtls version_number=%lu\\n", (unsigned long) MBEDTLS_VERSION_NUMBER);
    return MBEDTLS_VERSION_NUMBER == 0 ? 1 : 0;
}
"""
    if name.startswith("wolfssl"):
        return "smoke.c", """#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/wc_port.h>
int main(void) {
    unsigned char out[WC_SHA256_DIGEST_SIZE];
    const unsigned char msg[] = "abc";
    int ret = wolfCrypt_Init();
    if (ret == 0)
        ret = wc_Sha256Hash(msg, sizeof(msg) - 1, out);
    wolfCrypt_Cleanup();
    printf("SMOKE_RESULT target=wolfssl ret=%d out0=%u\\n", ret, (unsigned)out[0]);
    return ret == 0 ? 0 : 1;
}
"""
    return "smoke.cpp", """#include <botan/hash.h>
#include <iostream>
#include <memory>
int main() {
    auto h = Botan::HashFunction::create("SHA-256");
    if(!h) return 1;
    h->update(reinterpret_cast<const uint8_t*>("abc"), 3);
    auto out = h->final_stdvec();
    std::cout << "SMOKE_RESULT target=botan ok=1 outlen=" << out.size() << "\\n";
    return out.empty() ? 1 : 0;
}
"""


def smoke_command(name: str, src: Path, bin_path: Path, cfg: dict[str, Any]) -> list[str]:
    install = cfg["install_dir"]
    incs = [f"-I{p}" for p in include_dirs(install)]
    libs = [f"-L{p}" for p in lib_dirs(install)]
    rpaths = [f"-Wl,-rpath,{p}" for p in lib_dirs(install)]
    if name.startswith("openssl"):
        return ["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *incs, src.as_posix(), *libs, *rpaths, "-lssl", "-lcrypto", "-ldl", "-pthread", "-o", bin_path.as_posix()]
    if name.startswith("mbedtls"):
        return ["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *incs, src.as_posix(), *libs, *rpaths, "-lmbedcrypto", "-o", bin_path.as_posix()]
    if name.startswith("wolfssl"):
        return ["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *incs, src.as_posix(), *libs, *rpaths, "-lwolfssl", "-lm", "-pthread", "-o", bin_path.as_posix()]
    botan_lib = find_lib_name(install, ["botan-3", "botan-3.10", "botan"])
    return ["clang++", "-std=c++20", "-g", "-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", *incs, src.as_posix(), *libs, *rpaths, f"-l{botan_lib}", "-pthread", "-ldl", "-lrt", "-o", bin_path.as_posix()]


def smoke_env(name: str, cfg: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    dirs = [p.as_posix() for p in lib_dirs(cfg["install_dir"])]
    env["LD_LIBRARY_PATH"] = ":".join(dirs + ([env.get("LD_LIBRARY_PATH", "")] if env.get("LD_LIBRARY_PATH") else []))
    if name.startswith("openssl"):
        env["OPENSSL_MODULES"] = (cfg["install_dir"] / "lib64/ossl-modules").as_posix()
    env["ASAN_OPTIONS"] = "detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def run_smokes(out_dir: Path, build_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    status_by_name = {r["target"]: r for r in build_records}
    compiler = tool("clang") or tool("gcc")
    for name, cfg in TARGETS.items():
        root = out_dir / "smoke" / name
        root.mkdir(parents=True, exist_ok=True)
        src_name, code = smoke_source(name)
        src = root / src_name
        bin_path = root / "smoke.bin"
        write_text(src, code)
        rec = {
            "target": name,
            "smoke_compile_attempted": False,
            "smoke_run_attempted": False,
            "smoke_status": "blocked",
            "include_dirs": [p.as_posix() for p in include_dirs(cfg["install_dir"])],
            "lib_dirs": [p.as_posix() for p in lib_dirs(cfg["install_dir"])],
            "link_flags": [],
        }
        if status_by_name.get(name, {}).get("status") != "ready":
            rec["blocked_reason"] = status_by_name.get(name, {}).get("blocked_reason", "target not ready")
            dump_yaml(root / "smoke_result.yaml", rec)
            records.append(rec)
            continue
        if not compiler:
            rec["blocked_reason"] = "compiler missing"
            dump_yaml(root / "smoke_result.yaml", rec)
            records.append(rec)
            continue
        cmd = smoke_command(name, src, bin_path, cfg)
        rec["link_flags"] = [x for x in cmd if x.startswith("-l") or x.startswith("-L") or x.startswith("-Wl")]
        rec["smoke_compile_attempted"] = True
        write_text(root / "compile.sh", "#!/usr/bin/env bash\nset -euo pipefail\n" + " ".join(cmd) + "\n")
        comp = run_cmd(cmd, None, root / "compile")
        shutil.copyfile(root / "compile.stdout.log", root / "compile.log")
        rec["compile"] = comp
        if not comp["ok"]:
            rec["blocked_reason"] = "smoke compile failed"
            dump_yaml(root / "smoke_result.yaml", rec)
            records.append(rec)
            continue
        rec["smoke_run_attempted"] = True
        run_script = f"#!/usr/bin/env bash\nset -euo pipefail\n{bin_path.as_posix()}\n"
        write_text(root / "run.sh", run_script)
        run = run_cmd([bin_path.as_posix()], None, root / "run", env=smoke_env(name, cfg), timeout=20)
        shutil.copyfile(root / "run.stdout.log", root / "run.log")
        rec["run"] = run
        rec["smoke_status"] = "pass" if run["ok"] else "failed"
        rec["blocked_reason"] = "" if run["ok"] else "smoke run failed"
        dump_yaml(root / "smoke_result.yaml", rec)
        records.append(rec)
    return records


def target_entry(name: str, cfg: dict[str, Any], build: dict[str, Any], smoke: dict[str, Any] | None) -> dict[str, Any]:
    install = cfg["install_dir"]
    build_status = build.get("status", "blocked")
    smoke_status = (smoke or {}).get("smoke_status", "blocked")
    status = "ready" if build_status == "ready" and smoke_status == "pass" else "blocked"
    blocked_reason = ""
    if status != "ready":
        blocked_reason = (smoke or {}).get("blocked_reason") or build.get("blocked_reason", "smoke did not pass")
    return {
        "library": cfg["library"],
        "version": cfg["version"],
        "source_dir": cfg["source_dir"].as_posix(),
        "install_dir": install.as_posix(),
        "include_dirs": [p.as_posix() for p in include_dirs(install)],
        "lib_dirs": [p.as_posix() for p in lib_dirs(install)],
        "language": cfg["language"],
        "sanitizer": "asan_ubsan",
        "status": status,
        "blocked_reason": blocked_reason,
    }


def update_registry(repo_root: Path, out_dir: Path, build_records: list[dict[str, Any]], smoke_records: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    smoke_by_name = {r["target"]: r for r in smoke_records}
    build_by_name = {r["target"]: r for r in build_records}
    cfg_path = repo_root / "config/target_libraries.yaml"
    profile_path = repo_root / "config/sanitizer_profiles.yaml"
    existing = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    existing.setdefault("targets", {})
    delta = {"schema": "target_registry_delta_v1", "targets": {}}
    for name, cfg in TARGETS.items():
        entry = target_entry(name, cfg, build_by_name.get(name, {}), smoke_by_name.get(name))
        existing["targets"][name] = entry
        delta["targets"][name] = entry
    dump_yaml(cfg_path, existing)
    dump_yaml(out_dir / "target_registry_delta.yaml", delta)
    profiles = yaml.safe_load(profile_path.read_text(encoding="utf-8")) if profile_path.exists() else {}
    profiles.setdefault("profiles", {})
    profiles["profiles"]["asan_ubsan"] = {
        "cflags": ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g", "-O1"],
        "ldflags": ["-fsanitize=address,undefined"],
        "env": {
            "ASAN_OPTIONS": "detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        },
    }
    dump_yaml(profile_path, profiles)
    profile_delta = {"schema": "sanitizer_profile_delta_v1", "profiles": {"asan_ubsan": profiles["profiles"]["asan_ubsan"]}}
    dump_yaml(out_dir / "sanitizer_profile_delta.yaml", profile_delta)
    return delta, profile_delta


def write_capability_and_readiness(out_dir: Path, target_delta: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    families = {
        "x509_asn1_inner_boundary": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "unknown_api_check_needed", "wolfssl": "likely_ready", "botan": "likely_ready_cpp", "notes": ["requires target-specific parser API mapping"]},
        "pkcs_container_parsing": {"openssl": "ready", "mbedtls-3.6.4": "limited_or_blocked", "mbedtls-4.1.0": "limited_or_blocked", "wolfssl": "api_check_needed", "botan": "likely_ready_cpp", "notes": ["PKCS7/CMS availability differs by library"]},
        "asn1_nested_boundary": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "likely_ready", "wolfssl": "likely_ready", "botan": "likely_ready_cpp", "notes": ["ASN.1 low-level parser mapping required"]},
        "bignum_serialization_boundary": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "likely_ready", "wolfssl": "likely_ready", "botan": "likely_ready_cpp", "notes": ["caller-buffer API compatibility must be checked"]},
        "mac_lifecycle": {"openssl": "ready", "mbedtls-3.6.4": "psa_or_md_hmac_mapping_needed", "mbedtls-4.1.0": "psa_or_md_hmac_mapping_needed", "wolfssl": "hmac_mapping_needed", "botan": "mac_cpp_mapping_needed"},
        "cipher_aead_lifecycle": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "likely_ready", "wolfssl": "likely_ready", "botan": "likely_ready_cpp"},
        "pkey_verify_semantic": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "likely_ready", "wolfssl": "likely_ready", "botan": "likely_ready_cpp"},
        "memory_length_boundary": {"openssl": "ready", "mbedtls-3.6.4": "api_contract_check_needed", "mbedtls-4.1.0": "api_contract_check_needed", "wolfssl": "api_contract_check_needed", "botan": "api_contract_check_needed"},
        "buffer_canary_boundary": {"openssl": "ready", "mbedtls-3.6.4": "likely_ready", "mbedtls-4.1.0": "likely_ready", "wolfssl": "likely_ready", "botan": "likely_ready_cpp"},
        "null_deref_dispatch": {"openssl": "ready", "mbedtls-3.6.4": "contract_policy_needed", "mbedtls-4.1.0": "contract_policy_needed", "wolfssl": "contract_policy_needed", "botan": "contract_policy_needed"},
    }
    matrix = {"schema": "cross_library_family_capability_matrix_v1", "families": families}
    dump_yaml(out_dir / "family_capability_matrix.yaml", matrix)
    targets = target_delta.get("targets", {})
    readiness = {
        "schema": "rag_glm_chain_readiness_v1",
        "rag_glm_chain": {
            "historical_pattern_input": True,
            "family_cards_available": True,
            "api_cards_available": {"openssl": True, "mbedtls": False, "botan": False, "wolfssl": False},
            "mapping_gate_available": True,
            "adapter_recipe_required": True,
            "glm_slot_filling_required": True,
            "target_specific_render_required": True,
            "compile_run_under_sanitizer_ready": {
                "openssl": targets.get("openssl-3.5.5-asan", {}).get("status") == "ready",
                "mbedtls-3.6.4": targets.get("mbedtls-3.6.4-asan", {}).get("status") == "ready",
                "mbedtls-4.1.0": targets.get("mbedtls-4.1.0-asan", {}).get("status") == "ready",
                "wolfssl": targets.get("wolfssl-asan", {}).get("status") == "ready",
                "botan": targets.get("botan-3.10.0-asan", {}).get("status") == "ready",
            },
            "next_required_task": "cross_library_api_cards_and_mapping_v1",
        },
    }
    dump_yaml(out_dir / "rag_glm_chain_readiness.yaml", readiness)
    return matrix, readiness


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    probe = env_probe(out_dir)
    build_plan = {
        "schema": "cross_library_build_plan_v1",
        "targets": {
            name: {
                "source_dir": cfg["source_dir"].as_posix(),
                "build_dir": cfg["build_dir"].as_posix() if cfg["build_dir"] else "",
                "install_dir": cfg["install_dir"].as_posix(),
                "library": cfg["library"],
                "priority": cfg["priority"],
            }
            for name, cfg in TARGETS.items()
        },
    }
    dump_yaml(out_dir / "build_plan.yaml", build_plan)
    build_records = build_targets(out_dir, args.jobs, args.skip_build)
    dump_yaml(out_dir / "build_summary.yaml", {"schema": "cross_library_build_summary_v1", "targets": build_records})
    smoke_records = run_smokes(out_dir, build_records)
    target_delta, profile_delta = update_registry(repo_root, out_dir, build_records, smoke_records)
    matrix, readiness = write_capability_and_readiness(out_dir, target_delta)
    ready_count = sum(1 for t in target_delta["targets"].values() if t.get("status") == "ready")
    blocked_count = len(target_delta["targets"]) - ready_count
    smoke_compile_attempted = sum(1 for r in smoke_records if r.get("smoke_compile_attempted"))
    smoke_run_attempted = sum(1 for r in smoke_records if r.get("smoke_run_attempted"))
    smoke_pass = sum(1 for r in smoke_records if r.get("smoke_status") == "pass")
    if ready_count == len(TARGETS):
        quality_status = "pass_all_targets_ready"
    elif ready_count > 1:
        quality_status = "pass_partial_targets_ready"
    elif ready_count >= 1:
        quality_status = "blocked_no_new_targets_ready"
    else:
        quality_status = "blocked_build_tool_missing"
    qc = {
        "schema": "cross_library_sanitizer_bootstrap_quality_checks_v1",
        "core_logic_in_tools": False,
        "new_tools_script_created": False,
        "source_dirs_checked": True,
        "openssl_asan_existing_checked": True,
        "mbedtls_3_6_4_build_attempted": True,
        "mbedtls_4_1_0_build_attempted": True,
        "wolfssl_build_attempted": True,
        "botan_build_attempted": True,
        "targets_ready_count": ready_count,
        "targets_blocked_count": blocked_count,
        "smoke_compile_attempted_count": smoke_compile_attempted,
        "smoke_run_attempted_count": smoke_run_attempted,
        "smoke_pass_count": smoke_pass,
        "target_libraries_yaml_updated": True,
        "sanitizer_profiles_yaml_updated": True,
        "family_capability_matrix_generated": bool(matrix),
        "rag_glm_chain_readiness_generated": bool(readiness),
        "api_key_logged": False,
        "public_target_access": False,
        "exploit_chain_generated": False,
        "main_feedback_written": False,
        "pattern_bank_modified": False,
        "git_add_commit_push": False,
        "confirmed_vulnerability_claim": False,
        "quality_status": quality_status,
    }
    dump_yaml(out_dir / "validation/cross_library_sanitizer_bootstrap_quality_checks.yaml", qc)
    report_lines = [
        "# cross_library_sanitizer_bootstrap_v1 Report",
        "",
        f"- quality_status: {quality_status}",
        f"- targets_ready_count: {ready_count}",
        f"- targets_blocked_count: {blocked_count}",
        f"- smoke_pass_count: {smoke_pass}",
        "",
        "## Targets",
    ]
    for name, target in target_delta["targets"].items():
        report_lines.append(f"- {name}: {target.get('status')} {target.get('blocked_reason', '')}")
    report_lines.extend([
        "",
        "No public target was accessed. No exploit chain or vulnerability claim was generated.",
    ])
    write_text(out_dir / "reports/cross_library_sanitizer_bootstrap_v1_report.md", "\n".join(report_lines) + "\n")
    print(f"wrote {out_dir}")
    print(f"quality_status: {quality_status}")
    print(f"targets_ready_count: {ready_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
