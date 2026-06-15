"""Render constrained LLM repair prompts from repair_queue.jsonl."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


def _read_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _render_task(task: Dict[str, Any]) -> str:
    allowed = "\n".join(f"- {item}" for item in task.get("allowed_repair_scope", []))
    forbidden = "\n".join(f"- {item}" for item in task.get("forbidden_changes", []))
    rag_needed = "\n".join(f"- {item}" for item in task.get("rag_needed", []))
    if int(task.get("repair_attempt", 0)) >= int(task.get("max_attempts", 3)):
        status = "This case should be marked discarded_after_3_repairs."
    else:
        status = "Repair this case only within the allowed scope."
    return f"""## Repair Task: {task.get('case_id', '')}

{status}

case_path: {task.get('case_path', '')}
failure_type: {task.get('failure_type', '')}
repair_attempt: {task.get('repair_attempt', 0)}
max_attempts: {task.get('max_attempts', 3)}

Allowed repair scope:
{allowed}

Forbidden changes:
{forbidden}

RAG evidence needed:
{rag_needed}

Error excerpt:
```text
{task.get('error_excerpt', '')}
```

Requirements:
- Do not modify or remove the oracle.
- Do not disable sanitizer flags.
- Do not skip the trigger call.
- Do not change the expected verdict.
- Do not delete the failure path.
- Do not change mutation semantics.
- If this is the fourth failed attempt, mark it as discarded_after_3_repairs.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Render constrained repair prompt from queue.")
    parser.add_argument("--queue-jsonl", "--repair-queue", dest="queue_jsonl", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--max-tasks", type=int, default=20)
    args = parser.parse_args()

    tasks: List[Dict[str, Any]] = list(_read_jsonl(args.queue_jsonl))[: args.max_tasks]
    prompt = "\n\n".join(_render_task(task) for task in tasks)
    if not prompt:
        prompt = "No repairable tasks were found in the repair queue.\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt, encoding="utf-8")
    print(prompt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
