import argparse
from pathlib import Path
from typing import Any, Dict

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


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def indent(block: str, spaces: int = 4) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else "" for line in block.splitlines())


def sequence_block(case: Dict[str, Any]) -> str:
    case_id = case["case_id"]
    state = case["secure_heap_state"]
    seq = case["call_sequence"]
    expected = case.get("expected_control", "")

    header = f'''
install_crash_oracle();
printf("case_id={case_id}\\n");
printf("secure_heap_state={state}\\n");
printf("call_sequence={seq}\\n");
printf("expected_control={expected}\\n");
'''

    if state == "pre_init" and seq == "used_only":
        body = '''
size_t used = SECURE_HEAP_USED_API();
printf("CRYPTO_secure_used returned %zu\\n", used);
printf("[OK] secure_heap_state_lifecycle: pre_init used_only returned without crash\\n");
'''
    elif state == "initialized" and seq == "initialized_then_used":
        body = '''
int init_ret = SECURE_HEAP_INIT_API(4096, 32);
size_t used = SECURE_HEAP_USED_API();
printf("CRYPTO_secure_malloc_init returned %d\\n", init_ret);
printf("CRYPTO_secure_used returned %zu\\n", used);
if (init_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init failed\\n");
    return 2;
}
printf("[OK] secure_heap_state_lifecycle: initialized control returned defined value\\n");
SECURE_HEAP_DONE_API();
'''
    elif state == "initialized" and seq == "initialized_check_then_used":
        body = '''
int init_ret = SECURE_HEAP_INIT_API(4096, 32);
int initialized = SECURE_HEAP_INITIALIZED_CHECK_API();
printf("CRYPTO_secure_malloc_init returned %d\\n", init_ret);
printf("CRYPTO_secure_malloc_initialized returned %d\\n", initialized);
if (init_ret == 0 || !initialized) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init/check failed\\n");
    return 2;
}
size_t used = SECURE_HEAP_USED_API();
printf("CRYPTO_secure_used returned %zu\\n", used);
printf("[OK] secure_heap_state_lifecycle: initialized_check_then_used returned defined value\\n");
SECURE_HEAP_DONE_API();
'''
    elif state == "initialized_then_done" and seq == "done_then_used":
        body = '''
int init_ret = SECURE_HEAP_INIT_API(4096, 32);
int done_ret = SECURE_HEAP_DONE_API();
printf("CRYPTO_secure_malloc_init returned %d\\n", init_ret);
printf("CRYPTO_secure_malloc_done returned %d\\n", done_ret);
if (init_ret == 0 || done_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init/done failed\\n");
    return 2;
}
size_t used = SECURE_HEAP_USED_API();
printf("CRYPTO_secure_used returned %zu\\n", used);
printf("[OK] secure_heap_state_lifecycle: done_then_used returned without crash\\n");
'''
    elif state == "initialized_then_done_then_used" and seq == "initialized_check_then_used":
        body = '''
int init_ret = SECURE_HEAP_INIT_API(4096, 32);
int done_ret = SECURE_HEAP_DONE_API();
int initialized = SECURE_HEAP_INITIALIZED_CHECK_API();
printf("CRYPTO_secure_malloc_init returned %d\\n", init_ret);
printf("CRYPTO_secure_malloc_done returned %d\\n", done_ret);
printf("CRYPTO_secure_malloc_initialized returned %d\\n", initialized);
if (init_ret == 0 || done_ret == 0) {
    printf("[HARNESS_ERROR] secure_heap_state_lifecycle: init/done failed\\n");
    return 2;
}
if (!initialized) {
    printf("[OK] secure_heap_state_lifecycle: initialized check prevented post-done used call\\n");
    return 0;
}
size_t used = SECURE_HEAP_USED_API();
printf("CRYPTO_secure_used returned %zu\\n", used);
printf("[TRIAGE] secure_heap_state_lifecycle: post-done initialized check unexpectedly true\\n");
'''
    else:
        body = f'''
printf("[HARNESS_ERROR] secure_heap_state_lifecycle: unsupported matrix combination {state}/{seq}\\n");
return 2;
'''

    return indent(header + body, 4)


def render_case(template: str, case: Dict[str, Any]) -> str:
    rendered = template.replace("CRASH_ORACLE", CRASH_ORACLE.strip())
    rendered = rendered.replace("SECURE_HEAP_STATE_SEQUENCE", sequence_block(case))
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description="Render secure heap state lifecycle cases from a matrix.")
    parser.add_argument("--template", required=True)
    parser.add_argument("--matrix", required=True)
    parser.add_argument("--out-root", required=True)
    args = parser.parse_args()

    template_path = Path(args.template)
    matrix_path = Path(args.matrix)
    out_root = Path(args.out_root)

    template = template_path.read_text(encoding="utf-8")
    matrix = load_yaml(matrix_path)
    cases = matrix.get("cases", []) or []

    if not cases:
        print(f"[ERROR] no cases in matrix: {matrix_path}")
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
            "target_library": matrix.get("target_library", "openssl"),
            "target_api": matrix.get("target_api", "CRYPTO_secure_used"),
            "mutation_dimensions": {
                "secure_heap_state": case.get("secure_heap_state"),
                "call_sequence": case.get("call_sequence"),
            },
            "expected_control": case.get("expected_control", ""),
            "rendered_source": str(out_c),
        }
        with (out_dir / "case_manifest.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(manifest, f, allow_unicode=True, sort_keys=False)

        template_meta = {
            "template_id": "SECURE_HEAP_STATE_LIFECYCLE_V1_SOURCE_TEMPLATE",
            "pattern_id": matrix.get("seed_issue", "OPENSSL-ISSUE-28669"),
            "harness_family": matrix.get("family", "secure_heap_state_lifecycle"),
            "oracle_type": "secure_heap_preinit_crash_oracle",
            "target_library": matrix.get("target_library", "openssl"),
            "target_api": matrix.get("target_api", "CRYPTO_secure_used"),
            "render_matrix_case": manifest,
        }
        with (out_dir / "template_meta.yaml").open("w", encoding="utf-8") as f:
            yaml.safe_dump(template_meta, f, allow_unicode=True, sort_keys=False)

        print(f"[OK] rendered {case_id} -> {out_c}")

    print("=" * 80)
    print(f"[SUMMARY] rendered cases: {len(cases)}")
    print(f"[SUMMARY] output root: {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
