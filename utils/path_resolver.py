import os
from pathlib import Path
from typing import Any


PATH_LIST_KEYS = {
    "include_dirs",
    "lib_dirs",
    "library_dirs",
    "rpath_dirs",
    "source_dirs",
    "test_dirs",
}

PATH_SCALAR_KEYS = {
    "root",
    "path",
    "testvectors_dir",
}


def get_project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def get_clean_sources_root() -> Path:
    env_value = os.environ.get("CLEAN_SOURCES_ROOT")
    if env_value:
        expanded = os.path.expandvars(os.path.expanduser(env_value))
        p = Path(expanded)
        if p.is_absolute():
            return p.resolve()
        return (get_project_root() / p).resolve()
    return (get_project_root().parent / "clean_sources").resolve()


def _expand_path_vars(path: str) -> str:
    clean_sources_root = str(get_clean_sources_root())
    expanded = path.replace("${CLEAN_SOURCES_ROOT}", clean_sources_root)
    expanded = expanded.replace("$CLEAN_SOURCES_ROOT", clean_sources_root)
    return os.path.expandvars(os.path.expanduser(expanded))


def resolve_project_path(path: str | Path) -> Path:
    expanded = _expand_path_vars(str(path))
    p = Path(expanded)
    if p.is_absolute():
        return p.resolve()
    return (get_project_root() / p).resolve()


def resolve_external_path(path: str | Path) -> Path:
    expanded = _expand_path_vars(str(path))
    p = Path(expanded)
    if p.is_absolute():
        return p.resolve()
    return (get_project_root() / p).resolve()


def resolve_path_config(value: Any, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        return {k: resolve_path_config(v, k) for k, v in value.items()}

    if isinstance(value, list):
        if parent_key in PATH_LIST_KEYS:
            return [str(resolve_external_path(v)) for v in value]
        return [resolve_path_config(v, parent_key) for v in value]

    if isinstance(value, str) and parent_key in PATH_SCALAR_KEYS:
        return str(resolve_external_path(value))

    return value
