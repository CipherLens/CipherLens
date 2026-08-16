from __future__ import annotations

import argparse
from pathlib import Path

from analysis.candidate_context_pack import (
    build_context_pack_from_caller_discovery,
    write_context_pack,
)
from caller_audit.exploitability_runner import run_exploitability
from caller_audit.impact_runner import run_impactlift
from caller_audit.security_impact_runner import run_security_impact
from utils.codex_agent_provider import CodexAgentProvider


def default_output_root(caller_discovery: Path) -> Path:
    return caller_discovery.expanduser().resolve().parent / "impactlift"


def run_impactlift_from_discovery(
    caller_discovery_path: Path,
    *,
    output_root: Path | None = None,
    workspace: Path | None = None,
    timeout_seconds: int = 900,
) -> dict[str, Path]:
    caller_discovery_path = caller_discovery_path.expanduser().resolve()
    out_root = (
        output_root.expanduser().resolve()
        if output_root is not None
        else default_output_root(caller_discovery_path)
    )
    selected_workspace = (
        workspace.expanduser().resolve() if workspace is not None else Path.cwd().resolve()
    )
    out_root.mkdir(parents=True, exist_ok=True)

    context_pack_path = out_root / "candidate_context_pack.yaml"
    impact_exploration_path = out_root / "impact_exploration.yaml"
    exploitability_path = out_root / "exploitability.yaml"
    security_impact_path = out_root / "security_impact.yaml"

    context_pack = build_context_pack_from_caller_discovery(caller_discovery_path)
    write_context_pack(context_pack_path, context_pack)

    provider = CodexAgentProvider(
        selected_workspace,
        timeout_seconds=timeout_seconds,
    )
    run_impactlift(context_pack_path, impact_exploration_path, provider)
    run_exploitability(
        context_pack_path,
        impact_exploration_path,
        exploitability_path,
        provider,
    )
    run_security_impact(
        context_pack_path,
        impact_exploration_path,
        exploitability_path,
        security_impact_path,
        provider,
    )

    return {
        "output_root": out_root,
        "candidate_context_pack": context_pack_path,
        "impact_exploration": impact_exploration_path,
        "exploitability": exploitability_path,
        "security_impact": security_impact_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build an ImpactLift Context Pack from Caller Discovery and run ImpactLift v1."
    )
    parser.add_argument("--caller-discovery", type=Path, required=True)
    parser.add_argument(
        "--out-root",
        type=Path,
        default=None,
        help="Output root. Defaults to <caller-discovery-dir>/impactlift.",
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=Path.cwd(),
        help="Read-only workspace for the Codex ImpactLift provider.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()

    outputs = run_impactlift_from_discovery(
        args.caller_discovery,
        output_root=args.out_root,
        workspace=args.workspace,
        timeout_seconds=args.timeout_seconds,
    )
    print(f"[OK] ImpactLift from Caller Discovery: {outputs['output_root']}")
    print(f"[CONTEXT_PACK] {outputs['candidate_context_pack']}")
    print(f"[IMPACT_EXPLORATION] {outputs['impact_exploration']}")
    print(f"[EXPLOITABILITY] {outputs['exploitability']}")
    print(f"[SECURITY_IMPACT] {outputs['security_impact']}")


if __name__ == "__main__":
    main()
