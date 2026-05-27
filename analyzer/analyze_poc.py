import argparse
import re
from pathlib import Path
from typing import List, Dict, Any

import yaml


class NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True



API_PREFIXES = (
    "mbedtls_",
    "psa_",
    "BN_",
    "EVP_",
    "RSA_",
    "ECDSA_",
    "Botan::",
)

IGNORE_CALLS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "printf",
    "fprintf",
    "memset",
    "memcpy",
    "strlen",
    "setbuf",
    "calloc",
    "free",
    "goto",
}

TRIGGER_KEYWORDS = [
    "write_string",
    "sub_abs",
    "verify_ext",
    "decrypt",
    "encrypt",
    "sign",
    "verify",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def extract_includes(text: str) -> List[str]:
    includes = []
    for line in text.splitlines():
        m = re.match(r'\s*#\s*include\s+[<"]([^>"]+)[>"]', line)
        if m:
            includes.append(m.group(1))
    return includes


def extract_macros(text: str) -> Dict[str, str]:
    macros = {}
    for line in text.splitlines():
        m = re.match(r'\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$', line)
        if m:
            name, value = m.group(1), m.group(2)
            macros[name] = value.strip()
    return macros


def remove_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def collect_statements(text: str) -> List[str]:
    """
    Collect semicolon-ended statements and keep multiline function calls together.
    This is a lightweight approximation, enough for PoC-level analysis.
    """
    cleaned = remove_comments(text)
    stmts = []
    buf = []

    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        buf.append(stripped)

        if ";" in stripped:
            stmt = " ".join(buf)
            parts = stmt.split(";")
            for part in parts[:-1]:
                p = part.strip()
                if p:
                    stmts.append(p + ";")
            buf = [parts[-1].strip()] if parts[-1].strip() else []

    return stmts


def split_args(arg_text: str) -> List[str]:
    args = []
    cur = []
    depth = 0
    in_str = False
    quote = ""
    escape = False

    for ch in arg_text:
        if in_str:
            cur.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                in_str = False
            continue

        if ch in ("'", '"'):
            in_str = True
            quote = ch
            cur.append(ch)
            continue

        if ch in "([{":
            depth += 1
            cur.append(ch)
            continue

        if ch in ")]}":
            depth -= 1
            cur.append(ch)
            continue

        if ch == "," and depth == 0:
            arg = "".join(cur).strip()
            if arg:
                args.append(arg)
            cur = []
            continue

        cur.append(ch)

    tail = "".join(cur).strip()
    if tail:
        args.append(tail)

    return args


def extract_function_calls(text: str) -> List[Dict[str, Any]]:
    calls = []
    stmts = collect_statements(text)

    call_pattern = re.compile(r'([A-Za-z_][A-Za-z0-9_:]*)\s*\((.*)\)')

    for idx, stmt in enumerate(stmts):
        # Remove assignment prefix: ret = func(...)
        rhs = stmt.rstrip(";").strip()
        if "=" in rhs:
            rhs = rhs.split("=", 1)[1].strip()

        m = call_pattern.search(rhs)
        if not m:
            continue

        func = m.group(1)
        args_text = m.group(2).strip()

        if func in IGNORE_CALLS:
            continue

        args = split_args(args_text)

        is_api = func.startswith(API_PREFIXES)

        calls.append({
            "order": idx,
            "function": func,
            "args": args,
            "raw": stmt,
            "is_api": is_api,
        })

    return calls


def guess_library(includes: List[str], calls: List[Dict[str, Any]]) -> str:
    joined = "\n".join(includes + [c["function"] for c in calls])
    if "mbedtls/" in joined or "mbedtls_" in joined or "psa/" in joined or "psa_" in joined:
        return "mbedtls"
    if "openssl/" in joined or "BN_" in joined or "EVP_" in joined:
        return "openssl"
    if "botan" in joined.lower() or "Botan::" in joined:
        return "botan"
    return "unknown"


def guess_trigger_call(api_calls: List[Dict[str, Any]], user_trigger: str = "") -> Dict[str, Any]:
    if user_trigger:
        for c in api_calls:
            if c["function"] == user_trigger:
                return c

    for c in reversed(api_calls):
        name = c["function"]
        if any(k in name for k in TRIGGER_KEYWORDS):
            return c

    if api_calls:
        return api_calls[-1]

    return {}


def extract_oracle_functions(text: str) -> List[str]:
    candidates = []
    for name in ["canary_corrupted", "prepare_output_with_canary"]:
        if re.search(r'\b' + re.escape(name) + r'\s*\(', text):
            candidates.append(name)

    if "MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE" in text:
        candidates.append("fixed_ret_check:MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE")

    if "MBEDTLS_ERR_MPI_NEGATIVE_VALUE" in text:
        candidates.append("fixed_ret_check:MBEDTLS_ERR_MPI_NEGATIVE_VALUE")

    return candidates


def analyze_poc(path: Path, trigger_api: str = "") -> Dict[str, Any]:
    text = read_text(path)

    includes = extract_includes(text)
    macros = extract_macros(text)
    calls = extract_function_calls(text)
    api_calls = [c for c in calls if c["is_api"]]

    library = guess_library(includes, calls)
    trigger = guess_trigger_call(api_calls, trigger_api)
    oracle_functions = extract_oracle_functions(text)

    return {
        "source_file": str(path),
        "language": "c",
        "library": library,
        "includes": includes,
        "macros": macros,
        "function_calls": calls,
        "api_calls": api_calls,
        "trigger_call": trigger,
        "oracle_functions": oracle_functions,
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze C PoC and extract API call metadata.")
    parser.add_argument("poc", help="Path to PoC .c file")
    parser.add_argument(
        "-o", "--out",
        default="",
        help="Output YAML path. Default: analysis/<poc_name>.analysis.yaml",
    )
    parser.add_argument(
        "--trigger-api",
        default="",
        help="Optional trigger API name, e.g., mbedtls_mpi_write_string",
    )

    args = parser.parse_args()

    poc_path = Path(args.poc)
    if not poc_path.exists():
        raise FileNotFoundError(poc_path)

    result = analyze_poc(poc_path, trigger_api=args.trigger_api)

    out_path = Path(args.out) if args.out else Path("analysis") / f"{poc_path.stem}.analysis.yaml"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as f:
        yaml.dump(result, f, Dumper=NoAliasDumper, allow_unicode=True, sort_keys=False)

    print(f"[OK] analysis written to {out_path}")
    print(f"[INFO] library: {result['library']}")
    print(f"[INFO] api calls: {len(result['api_calls'])}")
    if result["trigger_call"]:
        print(f"[INFO] trigger: {result['trigger_call'].get('function')}")


if __name__ == "__main__":
    main()
