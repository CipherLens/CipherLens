"""Read-only integrity and deterministic-recomputation verifier for Batch 7C."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from evaluation_evidence.canonical import canonical_bytes
from evaluation_evidence.metric import evaluate_metric
from evaluation_evidence.registry import validate_document_or_raise
from pipeline_v2.artifact_store import ArtifactStore


def _load(store: ArtifactStore, link: Mapping[str, str]) -> dict[str, Any]:
    payload = store.get(str(link["ref"]), str(link["digest"]))
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{link['ref']}: expected JSON object")
    return value


def _resolve(store: ArtifactStore, ref: str) -> dict[str, str]:
    ref_hash = hashlib.sha256(ref.encode("utf-8")).hexdigest()
    association = store.root / "refs" / "sha256" / ref_hash[:2] / f"{ref_hash}.json"
    value = json.loads(association.read_text(encoding="utf-8"))
    return {"ref": value["artifact_ref"], "digest": value["artifact_digest"]}


def _verify_links(store: ArtifactStore, links: list[Mapping[str, str]], label: str) -> None:
    for link in links:
        if not store.verify(str(link["ref"]), str(link["digest"])):
            raise ValueError(f"{label}: invalid link {link}")


def verify(root: Path) -> dict[str, Any]:
    store = ArtifactStore(root)
    index = json.loads((root / "evaluation-index.json").read_text(encoding="utf-8"))
    for name, link in index.items():
        if not store.verify(link["ref"], link["digest"]):
            raise ValueError(f"index.{name}: ref/digest verification failed")
    summary = _load(store, index["summary"])
    ledger = _load(store, index["ledger"])
    validate_document_or_raise(ledger)

    verified_artifacts = 0
    for record in ledger["artifact_records"]:
        validate_document_or_raise(record)
        digest = record["artifact_digest"]
        if digest is not None:
            if not store.verify(record["artifact_ref"], digest):
                raise ValueError(f"artifact record failed verification: {record['artifact_ref']}")
            verified_artifacts += 1

    aggregate = {key: [] for key in ("passed", "failed", "skipped", "xfailed", "errors")}
    for record in ledger["test_run_records"]:
        validate_document_or_raise(record)
        _verify_links(store, [
            record["working_profile"], record["stdout_artifact"], record["stderr_artifact"],
            record["summary_artifact"], record["environment_profile"],
            *record["test_definition_refs"],
        ], "test_run_record")
        structured = _load(store, record["stdout_artifact"])
        recorded_summary = _load(store, record["summary_artifact"])
        if structured["counts"] != recorded_summary["counts"]:
            raise ValueError("structured stdout and summary counts differ")
        if structured["identities"] != recorded_summary["identities"]:
            raise ValueError("structured stdout and summary identities differ")
        for outcome, identities in recorded_summary["identities"].items():
            if len(identities) != record[outcome]:
                raise ValueError(f"test-run identity count mismatch for {outcome}")
            aggregate[outcome].extend(identities)
    if any(len(values) != len(set(values)) for values in aggregate.values()):
        raise ValueError("formal test identities are not unique within an outcome")
    counts = {key: len(value) for key, value in aggregate.items()}
    if counts != summary["formal_regression"]["counts"]:
        raise ValueError("summary test counts are not derived from TestRunRecords")
    if sum(counts.values()) != summary["formal_regression"]["population"]:
        raise ValueError("formal population does not equal exact outcome population")

    for unit in ledger["experiment_units"]:
        validate_document_or_raise(unit)
        _verify_links(store, unit["input_refs"] + unit["attempt_refs"] + unit["output_refs"], "experiment_unit")
    rq_counts: dict[str, int] = {}
    for rq in ("RQ1", "RQ2", "RQ3"):
        rq_counts[rq] = sum(rq in unit["research_question_refs"] for unit in ledger["experiment_units"])
    expected_units = {
        "RQ1": summary["experiments"]["rq1_units"],
        "RQ2": summary["experiments"]["rq2_units"],
        "RQ3": summary["experiments"]["rq3_units"],
    }
    if rq_counts != expected_units:
        raise ValueError("experiment population differs from summary")

    recomputed: dict[str, dict[str, Any]] = {}
    for record in ledger["metric_records"]:
        validate_document_or_raise(record)
        definition = _load(store, record["metric_definition"])
        manifest = _load(store, record["population_manifest"])
        validate_document_or_raise(definition)
        validate_document_or_raise(manifest)
        _verify_links(store, [
            *record["experiment_unit_refs"], *record["numerator_refs"], *record["denominator_refs"],
        ], "metric_record")
        actual = evaluate_metric(
            definition, manifest, resolver=store.verify, git_revision=record["git_revision"],
            experiment_unit_refs=record["experiment_unit_refs"],
            producer_id=record["producer"]["producer_id"],
            producer_version=record["producer"]["producer_version"],
        )
        if canonical_bytes(actual) != canonical_bytes(record):
            raise ValueError(f"metric recomputation mismatch: {definition['metric_name']}")
        recomputed[definition["metric_name"]] = {
            "numerator": actual["numerator_value"], "denominator": actual["denominator_value"],
            "recompute_status": actual["recompute_status"],
        }
    if recomputed != summary["metric_records"]:
        names = sorted(set(recomputed) | set(summary["metric_records"]))
        differences = [
            name for name in names if recomputed.get(name) != summary["metric_records"].get(name)
        ]
        raise ValueError(f"summary metrics differ from recomputed metric records: {differences}")

    structured_export = _load(store, _resolve(store, "exports/structured-evidence.json"))
    gate_reports = structured_export["report_evidence_view"] + structured_export["blocked_claim_view"]
    if len(gate_reports) != 6:
        raise ValueError("expected exactly six claim gate reports")
    for report in gate_reports:
        validate_document_or_raise(report)
        if not store.verify(report["claim"]["ref"], report["claim"]["digest"]):
            raise ValueError("claim gate points to invalid ClaimRecord")
    gate_distribution: dict[str, int] = {}
    for report in gate_reports:
        gate_distribution[report["gate_result"]] = gate_distribution.get(report["gate_result"], 0) + 1
    if gate_distribution.get("BLOCK") != 1 or gate_distribution.get("ALLOW_WITH_CAVEAT") != 5:
        raise ValueError("claim gate distribution violates the frozen evaluation boundary")

    if any(value != 0 for value in summary["policy_counters"].values()):
        raise ValueError("a forbidden external/provider/campaign counter is non-zero")
    if summary["implementation_defects"]:
        raise ValueError("formal evaluation records an implementation defect")
    return {
        "verified": True, "git_revision": summary["git_revision"],
        "test_population": summary["formal_regression"]["population"],
        "test_counts": counts, "test_run_records": len(ledger["test_run_records"]),
        "experiment_units": rq_counts, "metric_records": len(recomputed),
        "all_metrics_recomputed": True, "verified_artifact_records": verified_artifacts,
        "claim_gate_distribution": gate_distribution,
        "policy_counters": summary["policy_counters"],
        "ledger": index["ledger"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="artifacts/evaluation_v2")
    args = parser.parse_args()
    result = verify(Path(args.root))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
