import argparse
from pathlib import Path
from typing import Any, Dict, List

import yaml


CRASH_ORACLE = r'''
static void secure_heap_signal_handler(int signo)
{
    fprintf(stderr, "[CRASH] secure_heap_state_lifecycle: signal=%d\n", signo);
    fflush(stderr);
    _Exit(128 + signo);
}

static void install_crash_oracle(void)
{
    signal(SIGSEGV, secure_heap_signal_handler);
    signal(SIGABRT, secure_heap_signal_handler);
    signal(SIGBUS, secure_heap_signal_handler);
    signal(SIGILL, secure_heap_signal_handler);
}
'''


API_ROLES = {
    "CRYPTO_secure_used": "lifecycle_query",
    "CRYPTO_secure_malloc_initialized": "lifecycle_query",
    "CRYPTO_secure_allocated": "lifecycle_query",
    "OPENSSL_secure_malloc": "lifecycle_alloc",
    "OPENSSL_secure_zalloc": "lifecycle_alloc",
    "OPENSSL_secure_free": "lifecycle_free",
    "CRYPTO_secure_malloc_init": "lifecycle_init",
    "CRYPTO_secure_malloc_done": "lifecycle_done",
}


SEED_CASES = {
    ("CRYPTO_secure_used", "pre_init_query"),
    ("CRYPTO_secure_used", "done_then_query"),
}


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def indent(block: str, spaces: int = 4) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else "" for line in block.splitlines())


def c_string(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def query_call(api: str, ptr_name: str = "ptr") -> str:
    if api == "CRYPTO_secure_used":
        return '''
size_t used = CRYPTO_secure_used();
printf("query_api=CRYPTO_secure_used\\n");
printf("query_result_size=%zu\\n", used);
'''
    if api == "CRYPTO_secure_malloc_initialized":
        return '''
int initialized = CRYPTO_secure_malloc_initialized();
printf("query_api=CRYPTO_secure_malloc_initialized\\n");
printf("query_result_int=%d\\n", initialized);
'''
    if api == "CRYPTO_secure_allocated":
        return f'''
int allocated = CRYPTO_secure_allocated({ptr_name});
printf("query_api=CRYPTO_secure_allocated\\n");
printf("query_result_int=%d\\n", allocated);
'''
    raise ValueError(f"unsupported query api: {api}")


def allocation_call(api: str) -> str:
    if api not in {"OPENSSL_secure_malloc", "OPENSSL_secure_zalloc"}:
        raise ValueError(f"unsupported allocation api: {api}")
    return f'''
void *ptr = {api}(32);
printf("alloc_api={api}\\n");
printf("alloc_ptr=%p\\n", ptr);
if (ptr != NULL) {{
    OPENSSL_secure_free(ptr);
    printf("alloc_cleanup=OPENSSL_secure_free\\n");
}}
'''


def state_block(case: Dict[str, Any]) -> str:
    api = str(case["api_under_test"])
    state = str(case["state_sequence"])
    case_id = str(case["case_id"])
    expected = str(case.get("expected_control", ""))
    role = str(case.get("api_role") or API_ROLES.get(api, "unknown"))
    novelty = str(case.get("novelty_scope", ""))
    is_seed = "true" if case.get("is_seed_case") else "false"

    header = f'''
install_crash_oracle();
printf("case_id={c_string(case_id)}\\n");
printf("api_under_test={c_string(api)}\\n");
printf("api_role={c_string(role)}\\n");
printf("state_sequence={c_string(state)}\\n");
printf("is_seed_case={is_seed}\\n");
printf("expected_control={c_string(expected)}\\n");
printf("novelty_scope={c_string(novelty)}\\n");
'''

    if state == "pre_init_query" and role == "lifecycle_query":
        ptr_setup = "void *ptr = NULL;\n" if api == "CRYPTO_secure_allocated" else ""
        body = ptr_setup + query_call(api)
    elif state == "initialized_query" and role == "lifecycle_query":
        ptr_setup = ""
        if api == "CRYPTO_secure_allocated":
            ptr_setup = '''
void *ptr = OPENSSL_secure_malloc(32);
printf("control_alloc_ptr=%p\\n", ptr);
'''
        else:
            ptr_setup = "void *ptr = NULL;\n"
        body = f'''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}}
{ptr_setup}
''' + query_call(api) + '''
if (ptr != NULL)
    OPENSSL_secure_free(ptr);
CRYPTO_secure_malloc_done();
printf("[OK] secure_heap_state_lifecycle: initialized query control completed\\n");
'''
    elif state == "done_then_query" and role == "lifecycle_query":
        body = f'''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}}
int done_ret = CRYPTO_secure_malloc_done();
printf("done_ret=%d\\n", done_ret);
if (done_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: done failed\\n");
    return 2;
}}
void *ptr = NULL;
''' + query_call(api)
    elif state == "done_twice" and api == "CRYPTO_secure_malloc_done":
        body = '''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}
int first_done = CRYPTO_secure_malloc_done();
int second_done = CRYPTO_secure_malloc_done();
printf("first_done=%d\\n", first_done);
printf("second_done=%d\\n", second_done);
printf("[OK] secure_heap_state_lifecycle: done_twice completed\\n");
'''
    elif state == "reinit_after_done" and api == "CRYPTO_secure_malloc_init":
        body = '''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: first init failed\\n");
    return 2;
}
int done_ret = CRYPTO_secure_malloc_done();
printf("done_ret=%d\\n", done_ret);
int reinit_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("reinit_ret=%d\\n", reinit_ret);
if (reinit_ret != 0)
    CRYPTO_secure_malloc_done();
printf("[OK] secure_heap_state_lifecycle: reinit_after_done completed\\n");
'''
    elif state == "done_then_alloc" and role == "lifecycle_alloc":
        body = f'''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}}
int done_ret = CRYPTO_secure_malloc_done();
printf("done_ret=%d\\n", done_ret);
if (done_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: done failed\\n");
    return 2;
}}
''' + allocation_call(api)
    elif state == "done_then_free" and api == "OPENSSL_secure_free":
        body = '''
void *ptr = OPENSSL_malloc(32);
printf("plain_malloc_ptr=%p\\n", ptr);
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {
    OPENSSL_free(ptr);
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}
int done_ret = CRYPTO_secure_malloc_done();
printf("done_ret=%d\\n", done_ret);
if (done_ret == 0) {
    OPENSSL_free(ptr);
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: done failed\\n");
    return 2;
}
OPENSSL_secure_free(ptr);
printf("[OK] secure_heap_state_lifecycle: done_then_free completed\\n");
'''
    elif state == "alloc_then_done_then_free" and api == "OPENSSL_secure_free":
        body = '''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}
void *ptr = OPENSSL_secure_malloc(32);
printf("secure_alloc_ptr=%p\\n", ptr);
int done_with_live_alloc = CRYPTO_secure_malloc_done();
printf("done_with_live_alloc=%d\\n", done_with_live_alloc);
if (ptr != NULL)
    OPENSSL_secure_free(ptr);
int done_after_free = CRYPTO_secure_malloc_done();
printf("done_after_free=%d\\n", done_after_free);
printf("[OK] secure_heap_state_lifecycle: alloc_then_done_then_free completed\\n");
'''
    elif state == "init_failed_then_query" and role == "lifecycle_query":
        body = '''
int init_ret = CRYPTO_secure_malloc_init(16, 16);
printf("failed_init_ret=%d\\n", init_ret);
if (init_ret != 0) {
    printf("[TRIAGE] secure_heap_state_lifecycle: expected invalid init to fail\\n");
    CRYPTO_secure_malloc_done();
}
void *ptr = NULL;
''' + query_call(api)
    elif state == "initialized_alloc_free_control" and role == "lifecycle_alloc":
        body = f'''
int init_ret = CRYPTO_secure_malloc_init(4096, 32);
printf("init_ret=%d\\n", init_ret);
if (init_ret == 0) {{
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}}
void *ptr = {api}(32);
printf("alloc_api={api}\\n");
printf("alloc_ptr=%p\\n", ptr);
if (ptr != NULL)
    OPENSSL_secure_free(ptr);
int done_ret = CRYPTO_secure_malloc_done();
printf("done_ret=%d\\n", done_ret);
printf("[OK] secure_heap_state_lifecycle: initialized alloc/free control completed\\n");
'''
    else:
        body = f'''
printf("[HARNESS_ERROR] secure_heap_state_lifecycle: unsupported expansion combination {c_string(api)}/{c_string(state)}\\n");
return 2;
'''

    return indent(header + body + '\nprintf("[OK] secure_heap_state_lifecycle: case completed without crash\\n");\n', 4)


def render_case(template: str, case: Dict[str, Any]) -> str:
    rendered = template.replace("CRASH_ORACLE", CRASH_ORACLE.strip())
    return rendered.replace("SECURE_HEAP_STATE_SEQUENCE", state_block(case))


def planned_cases(matrix: Dict[str, Any]) -> List[Dict[str, Any]]:
    explicit = matrix.get("cases")
    if explicit:
        return list(explicit)

    cases: List[Dict[str, Any]] = []
    for idx, entry in enumerate(matrix.get("case_matrix", []) or []):
        api = str(entry["api_under_test"])
        state = str(entry["state_sequence"])
        role = API_ROLES.get(api, "unknown")
        seed = (api, state) in SEED_CASES
        novelty = "historical_reproduction" if seed else entry.get("novelty_scope", "")
        if not novelty:
            novelty = "new_api_candidate" if api != "CRYPTO_secure_used" else "new_state_combination_candidate"
        cases.append({
            "case_id": entry.get("case_id", f"secure_heap_exp_{idx:04d}_{api.lower()}_{state}"),
            "api_under_test": api,
            "api_role": entry.get("api_role", role),
            "state_sequence": state,
            "is_seed_case": bool(seed or entry.get("is_seed_case", False)),
            "expected_control": entry.get("expected_control", "no_crash_or_documented_precondition_failure"),
            "novelty_scope": novelty,
            "skip_reason": entry.get("skip_reason", ""),
        })
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Render secure heap state lifecycle expansion cases.")
    parser.add_argument("--template", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out-root", required=True)
    parser.add_argument("--max-cases", type=int, default=40)
    args = parser.parse_args()

    template = Path(args.template).read_text(encoding="utf-8")
    matrix = load_yaml(Path(args.matrix))
    out_root = Path(args.out_root)
    cases = [c for c in planned_cases(matrix) if not c.get("skip_reason")]
    cases = cases[: args.max_cases]

    if not cases:
        print(f"[ERROR] no renderable cases in matrix: {args.matrix}")
        return 1

    for case in cases:
        case_id = str(case["case_id"])
        out_dir = out_root / case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        out_c = out_dir / f"{case_id}_openssl.c"
        write_text(out_c, render_case(template, case))

        manifest = {
            "case_id": case_id,
            "family": matrix.get("family", "secure_heap_state_lifecycle"),
            "seed_issue": matrix.get("seed_issue", "OPENSSL-ISSUE-28669"),
            "execution_mode": matrix.get("execution_mode", "same_family_state_expansion"),
            "target_library": "openssl",
            "api_under_test": case.get("api_under_test"),
            "api_role": case.get("api_role"),
            "state_sequence": case.get("state_sequence"),
            "is_seed_case": bool(case.get("is_seed_case")),
            "expected_control": case.get("expected_control"),
            "novelty_scope": case.get("novelty_scope"),
            "rendered_source": str(out_c),
        }
        with (out_dir / "case_manifest.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)

        template_meta = {
            "template_id": "SECURE_HEAP_STATE_LIFECYCLE_PATTERN_EXPANSION_V1",
            "pattern_id": matrix.get("seed_issue", "OPENSSL-ISSUE-28669"),
            "harness_family": matrix.get("family", "secure_heap_state_lifecycle"),
            "oracle_type": "secure_heap_lifecycle_robustness_oracle",
            "target_library": "openssl",
            "target_api": case.get("api_under_test"),
            "render_matrix_case": manifest,
        }
        with (out_dir / "template_meta.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(template_meta, f, allow_unicode=True, sort_keys=False)

        print(f"[OK] rendered {case_id} -> {out_c}")

    skipped = [c for c in planned_cases(matrix) if c.get("skip_reason")]
    print("=" * 80)
    print(f"[SUMMARY] rendered cases: {len(cases)}")
    print(f"[SUMMARY] skipped cases: {len(skipped)}")
    print(f"[SUMMARY] output root: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
