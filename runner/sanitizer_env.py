"""Shared sanitizer OpenSSL environment helpers for family-level runners."""

from __future__ import annotations

import os
import signal
from pathlib import Path


SANITIZER_KEYWORDS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "use-after-free",
    "double-free",
    "invalid free",
    "SEGV",
    "ABRT",
    "timeout",
]


def rel(path: str | Path) -> str:
    return Path(path).as_posix()


def lib_dir_for_install(install: Path) -> Path:
    lib64 = install / "lib64"
    if lib64.exists():
        return lib64
    return install / "lib"


def signal_name(returncode: int | None) -> str:
    if returncode is None or returncode >= 0:
        return ""
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except ValueError:
        return f"SIG{sig}"


def sanitizer_kinds(text: str) -> list[str]:
    kinds: list[str] = []
    if "AddressSanitizer" in text:
        kinds.append("asan")
    if "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        kinds.append("ubsan")
    if "LeakSanitizer" in text:
        kinds.append("lsan")
    return sorted(set(kinds))


def matched_keywords(text: str) -> list[str]:
    return [kw for kw in SANITIZER_KEYWORDS if kw in text]


def raw_excerpt(text: str, max_lines: int = 12) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:max_lines])


def run_env(install: Path, lib_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    prior = env.get("LD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = f"{lib_dir}:{prior}" if prior else rel(lib_dir)
    env["OPENSSL_MODULES"] = rel(lib_dir / "ossl-modules")
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=1:symbolize=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return env


def asan_options() -> str:
    return "detect_leaks=0:abort_on_error=1:symbolize=1"


def ubsan_options() -> str:
    return "halt_on_error=1:print_stacktrace=1"
