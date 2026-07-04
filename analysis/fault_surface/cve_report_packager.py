"""Package final security verdict artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from analysis.fault_surface.cve_final_verdict_engine import CONFIRMATION_VERDICT


class CVEReportPackager:
    """Build deterministic report artifacts for the final verdict."""

    schema = "cve_report_packager_v1"

    def build(
        self,
        seed_context: Mapping[str, Any],
        unified_runtime_truth: Mapping[str, Any],
        final_security_verdict: Mapping[str, Any],
        exploitability_score: Mapping[str, Any],
    ) -> dict[str, Any]:
        verdict = final_security_verdict.get("verdict")
        affected = _affected_libraries(unified_runtime_truth)
        impact_analysis = {
            "schema": "impact_analysis_v1",
            "verdict": verdict,
            "exploitability_score": exploitability_score.get("exploitability_score", 0),
            "security_impacting_api_mismatch": final_security_verdict.get("security_impacting_api_mismatch"),
            "runtime_reproducible_divergence": final_security_verdict.get("runtime_reproducible_divergence"),
            "candidate_queue_written": False,
        }
        affected_libraries = {
            "schema": "affected_libraries_v1",
            "libraries": affected,
            "source": "unified_runtime_truth",
            "candidate_queue_written": False,
        }
        security_summary = _security_summary(seed_context, final_security_verdict, affected)
        payloads: dict[str, Any] = {
            "impact_analysis.yaml": impact_analysis,
            "affected_libraries.yaml": affected_libraries,
            "security_summary.md": security_summary,
        }
        if verdict == CONFIRMATION_VERDICT:
            payloads["minimal_reproducer.c"] = _minimal_reproducer(seed_context, affected)
        return {
            "schema": self.schema,
            "verdict": verdict,
            "report_payloads": payloads,
            "candidate_queue_written": False,
            "claim_level": "report_packaging_only",
        }


def build(
    seed_context: Mapping[str, Any],
    unified_runtime_truth: Mapping[str, Any],
    final_security_verdict: Mapping[str, Any],
    exploitability_score: Mapping[str, Any],
) -> dict[str, Any]:
    """Build final verdict report artifacts."""

    return CVEReportPackager().build(
        seed_context,
        unified_runtime_truth,
        final_security_verdict,
        exploitability_score,
    )


def _affected_libraries(unified_runtime_truth: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = [row for row in unified_runtime_truth.get("rows", []) if isinstance(row, Mapping)]
    return [
        {
            "library": row.get("library"),
            "authoritative_source": row.get("authoritative_source"),
            "outcome_signature": row.get("outcome_signature", {}),
        }
        for row in rows
        if row.get("truth_status") == "authoritative"
    ]


def _security_summary(
    seed_context: Mapping[str, Any],
    final_security_verdict: Mapping[str, Any],
    affected: list[Mapping[str, Any]],
) -> str:
    seed_id = seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed"
    libraries = ", ".join(str(item.get("library")) for item in affected) or "none"
    return (
        f"# Final Security Verdict Summary\n\n"
        f"- seed_id: `{seed_id}`\n"
        f"- verdict: `{final_security_verdict.get('verdict')}`\n"
        f"- libraries: `{libraries}`\n"
        f"- source: unified runtime truth and reconciled oracle only\n"
        f"- candidate_queue_written: `false`\n"
    )


def _minimal_reproducer(seed_context: Mapping[str, Any], affected: list[Mapping[str, Any]]) -> str:
    seed_id = seed_context.get("seed_id") or seed_context.get("seed_candidate_id") or "unknown_seed"
    libraries = ", ".join(str(item.get("library")) for item in affected)
    return f"""/*
 * Deterministic same-seed replay scaffold.
 * This is emitted only when the final verdict rule is satisfied.
 * seed_id: {seed_id}
 * libraries: {libraries}
 */
#include <stdio.h>

int main(void) {{
    puts("load seed bytes through the existing seed-driven renderer");
    puts("run the same input against each affected library");
    puts("compare unified runtime truth observables");
    return 0;
}}
"""
