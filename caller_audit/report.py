from __future__ import annotations

from typing import Any


def render_report(result: dict[str, Any]) -> str:
    project = result["project"]
    candidate = result["candidate"]
    repository = result["repository"]
    static = result["static_checks"]
    dynamic = result["dynamic_evidence"]
    verdict = result["verdict"]

    lines = [
        "# CipherLens Caller Audit v0.1",
        "",
        "## Target",
        "",
        f"- Project: `{project.get('name', '')}`",
        f"- Commit: `{repository.get('commit', '')}`",
        f"- Candidate API: `{candidate.get('target_api', '')}`",
        f"- Source case: `{candidate.get('source_case', '')}`",
        "",
        "## Static audit",
        "",
        f"- Call sites: {static.get('call_site_count', 0)}",
        (
            "- Production call sites without nearby "
            "full-consumption check: "
            f"{static.get('production_without_full_consumption_check', 0)}"
        ),
        "",
        "## Dynamic evidence",
        "",
        f"- Baseline passed: `{dynamic.get('baseline_passed', False)}`",
        (
            "- Mutation candidate confirmed: "
            f"`{dynamic.get('mutation_candidate_confirmed', False)}`"
        ),
        f"- Fix control passed: `{dynamic.get('fix_control_passed', False)}`",
        f"- ASan error: `{dynamic.get('asan_error', False)}`",
        f"- UBSan error: `{dynamic.get('ubsan_error', False)}`",
        "",
        "## Verdict",
        "",
        f"**{verdict.get('status', 'unknown')}**",
        "",
        verdict.get("reason", ""),
        "",
        "The v0.1 verdict requires per-case evidence and a patched "
        "fix-control regression before a caller behavior is considered "
        "fully reproduced.",
        "",
    ]
    return "\n".join(lines)
