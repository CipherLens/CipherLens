import json
from pathlib import Path

path = Path("data/jsonl/wolfssl_code_localization_eval_v1.jsonl")

required_top_fields = [
    "sample_id",
    "library",
    "task_type",
    "pattern_id",
    "related_pocs",
    "prompt",
    "recipe",
    "poc_metadata",
    "expected_output_schema",
    "source_context",
    "vulnerable_code",
    "fixed_code",
    "masked_code",
    "ground_truth",
    "ground_truth_answer",
]

required_ground_truth_fields = [
    "file",
    "function",
    "vulnerable_operation",
    "guard_condition",
    "destination_capacity",
    "matched_recipe_slots",
]

count = 0
errors = []

for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue

    count += 1
    obj = json.loads(line)

    for field in required_top_fields:
        if field not in obj:
            errors.append(f"line {lineno}: missing top-level field {field}")

    gt = obj.get("ground_truth", {})
    for field in required_ground_truth_fields:
        if field not in gt:
            errors.append(f"line {lineno}: missing ground_truth field {field}")

    for code_field in ["vulnerable_code", "fixed_code"]:
        code_obj = obj.get(code_field, {})
        if not code_obj.get("code"):
            errors.append(f"line {lineno}: empty {code_field}.code")
        if not code_obj.get("start_line"):
            errors.append(f"line {lineno}: missing {code_field}.start_line")
        if not code_obj.get("end_line"):
            errors.append(f"line {lineno}: missing {code_field}.end_line")

    if "MASKED" not in obj.get("masked_code", ""):
        errors.append(f"line {lineno}: masked_code has no MASKED marker")

print("validated_samples:", count)

if errors:
    print("validation_status: FAILED")
    for e in errors:
        print(e)
    raise SystemExit(1)

print("validation_status: OK")
