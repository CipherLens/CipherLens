import argparse
import json
from pathlib import Path


def load_recipes(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def find_pattern(data, pattern_id):
    for p in data.get("patterns", []):
        if p.get("pattern_id") == pattern_id:
            return p
    raise SystemExit(f"pattern not found: {pattern_id}")


def format_slots(slots):
    lines = []
    for name, info in slots.items():
        role = info.get("role", "")
        observed = info.get("observed_value", info.get("observed_variable", info.get("observed_expression", "")))
        mutation = info.get("mutation", "")
        line = f"- {name}: {role}"
        if observed != "":
            line += f" | observed: {observed}"
        if mutation != "":
            line += f" | mutation: {mutation}"
        lines.append(line)
    return "\n".join(lines)


def build_prompt(pattern):
    bug_mechanism = pattern.get("bug_mechanism", {})
    oracle = pattern.get("oracle", {})

    return f"""# Vulnerability Pattern Analysis Prompt

## Pattern

- Pattern ID: {pattern.get("pattern_id")}
- Name: {pattern.get("name")}
- Related PoC: {", ".join(pattern.get("related_pocs", []))}
- Trigger surface: {pattern.get("trigger_surface")}
- Input type: {pattern.get("input_type")}
- Quality level: {pattern.get("quality_level")}

## Bug Mechanism

Core issue:

{bug_mechanism.get("core_issue", "")}

Trust boundary:

{bug_mechanism.get("trust_boundary", "")}

Vulnerable operation:

{bug_mechanism.get("vulnerable_operation", "")}

Failure modes:

{", ".join(bug_mechanism.get("failure_mode", []))}

## Recipe Slots

{format_slots(pattern.get("recipe_slots", {}))}

## Mutation Strategy

{chr(10).join(f"- {x}" for x in pattern.get("mutation_strategy", []))}

## Oracle

Primary oracle: {oracle.get("primary", "")}

Signals:

{chr(10).join(f"- {x}" for x in oracle.get("signals", []))}

Fixed behavior:

{chr(10).join(f"- {x}" for x in oracle.get("fixed_behavior", []))}

## AST Masking Targets

{chr(10).join(f"- {x}" for x in pattern.get("ast_masking_targets", []))}

## RAG Keywords

{", ".join(pattern.get("rag_keywords", []))}

## Task

You are given source code from a cryptographic library.

Find code regions that may implement the same vulnerability pattern.

Focus on:

1. Whether untrusted ASN.1 / X.509 length or count values cross into fixed-size buffers.
2. Whether the checked length differs from the copied length.
3. Whether setter APIs store untrusted length without capacity validation.
4. Whether getter, text extraction, or DER re-encoding paths trust previously stored values.
5. Whether compatibility APIs copy into caller-provided buffers.

For each suspicious code region, report:

- Function name
- File path
- Relevant variables
- Guard condition
- Copy or write operation
- Destination capacity
- Why it matches this pattern
- A suggested mutation or test input shape
"""


def main():
    parser = argparse.ArgumentParser(
        description="Build an LLM/RAG prompt from a wolfSSL pattern recipe."
    )
    parser.add_argument("pattern_id", help="Pattern ID, e.g. Pattern-04")
    parser.add_argument(
        "--file",
        default="inventory/wolfssl_pattern_recipes.json",
        help="Recipe JSON path."
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional output file path."
    )

    args = parser.parse_args()

    data = load_recipes(args.file)
    pattern = find_pattern(data, args.pattern_id)
    prompt = build_prompt(pattern)

    if args.out:
        Path(args.out).write_text(prompt, encoding="utf-8")
        print(f"[OK] wrote {args.out}")
    else:
        print(prompt)


if __name__ == "__main__":
    main()
