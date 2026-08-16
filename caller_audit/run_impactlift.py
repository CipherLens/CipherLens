from __future__ import annotations

import argparse
from pathlib import Path

from caller_audit.impact_runner import run_impactlift
from utils.codex_agent_provider import CodexAgentProvider


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run ImpactLift exploration v1 with the fixed Codex backend."
    )
    parser.add_argument("--context-pack", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    provider = CodexAgentProvider(
        args.workspace,
        timeout_seconds=args.timeout_seconds,
    )
    artifact = run_impactlift(
        args.context_pack,
        args.out,
        provider,
    )
    result = artifact["result"]
    print(f"[OK] ImpactLift exploration: {args.out}")
    print(f"[PROVIDER] {artifact['provider']['name']}")
    print(f"[MODEL] {artifact['provider']['model']}")
    print(f"[REASONING] {artifact['provider']['reasoning_effort']}")
    print(f"[CONFIDENCE] {result['confidence']}")


if __name__ == "__main__":
    main()
