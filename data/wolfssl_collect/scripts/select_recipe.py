import argparse
import json
from pathlib import Path


def as_text_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value]
    return [str(value)]


def flatten_pattern_text(pattern):
    parts = []

    scalar_keys = [
        "pattern_id",
        "name",
        "bug_class",
        "trigger_surface",
        "input_type",
        "input_provenance",
        "quality_level",
    ]

    for key in scalar_keys:
        parts.append(str(pattern.get(key, "")))

    parts.extend(as_text_list(pattern.get("related_pocs")))
    parts.extend(as_text_list(pattern.get("dataset_tags")))
    parts.extend(as_text_list(pattern.get("rag_keywords")))
    parts.extend(as_text_list(pattern.get("ast_masking_targets")))
    parts.extend(as_text_list(pattern.get("mutation_strategy")))

    bug_mechanism = pattern.get("bug_mechanism", {})
    if isinstance(bug_mechanism, dict):
        parts.extend(str(v) for v in bug_mechanism.values())

    recipe_slots = pattern.get("recipe_slots", {})
    if isinstance(recipe_slots, dict):
        for slot_name, slot_value in recipe_slots.items():
            parts.append(str(slot_name))
            if isinstance(slot_value, dict):
                parts.extend(str(v) for v in slot_value.values())
            else:
                parts.append(str(slot_value))

    oracle = pattern.get("oracle", {})
    if isinstance(oracle, dict):
        parts.extend(str(v) for v in oracle.values())

    return "\n".join(parts).lower()


def main():
    parser = argparse.ArgumentParser(
        description="Select wolfSSL vulnerability pattern recipes by keyword."
    )
    parser.add_argument(
        "query",
        nargs="*",
        help="Keyword(s) to search, e.g. x509 akid memcpy length-confusion"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full matching pattern objects as JSON."
    )
    parser.add_argument(
        "--file",
        default="inventory/wolfssl_pattern_recipes.json",
        help="Recipe JSON path."
    )

    args = parser.parse_args()

    path = Path(args.file)
    data = json.loads(path.read_text(encoding="utf-8"))
    patterns = data.get("patterns", [])

    queries = [q.lower() for q in args.query]

    matches = []
    for pattern in patterns:
        text = flatten_pattern_text(pattern)
        if not queries or all(q in text for q in queries):
            matches.append(pattern)

    if args.json:
        print(json.dumps(matches, indent=2, ensure_ascii=False))
        return

    print(f"matched_patterns: {len(matches)}")

    for p in matches:
        print()
        print(f"- {p.get('pattern_id')}: {p.get('name')}")
        print(f"  related_pocs: {', '.join(p.get('related_pocs', []))}")
        print(f"  trigger_surface: {p.get('trigger_surface')}")
        print(f"  input_type: {p.get('input_type')}")
        print(f"  quality_level: {p.get('quality_level')}")
        print(f"  tags: {', '.join(p.get('dataset_tags', []))}")

        slots = p.get("recipe_slots", {})
        if slots:
            print(f"  slots: {', '.join(slots.keys())}")


if __name__ == "__main__":
    main()
