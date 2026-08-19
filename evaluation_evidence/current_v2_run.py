"""Run the frozen Batch 7C local CURRENT_V2 engineering evaluation.

The runner performs no network or real-provider work.  It records formal test
runs, executes synthetic/golden controlled experiments, deterministically
recomputes metrics, and emits claim-gated machine-readable evidence.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from typing import Any, Iterable, Mapping
from unittest.mock import patch

from candidate_binding.canonical import canonical_candidate_binding_bytes, canonical_validation_bytes
from evaluation_evidence.canonical import canonical_bytes, canonical_json_bytes, document_digest, identify
from evaluation_evidence.claim_gate import build_claim_record, claim_link, evaluate_claim, metric_link
from evaluation_evidence.export import structured_evidence_export
from evaluation_evidence.inventory import build_artifact_record
from evaluation_evidence.ledger import build_evidence_ledger
from evaluation_evidence.metric import build_experiment_unit, build_population_manifest, evaluate_metric
from evaluation_evidence.model import (
    ClaimTaxonomy, EvidenceOrigin, InventoryState, SCHEMA_VERSIONS, ValidationMaturity,
)
from evaluation_evidence.registry import INITIAL_METRIC_REGISTRY, validate_document_or_raise
from evaluation_evidence.test_record import record_test_run
from execution_model.canonical import canonical_json_bytes as execution_canonical_bytes
from execution_pipeline.collect_adapter import sanitizer_evidence
from execution_pipeline.runner_adapter import attempt_outcome
from execution_trace.closure import build_unknown_closure
from execution_trace.legacy_import import import_legacy_result
from pipeline_v2.artifact_store import ArtifactRef, ArtifactStore
from template_binding_merge.completion import programmatic_complete
from template_binding_merge.model import ValidationContext
from template_binding_merge.registry import validate_merged_source
from template_binding_merge.render import render_base_source
from tests.execution_support import built_record, chain
from tests.matcher.common import case_request
from tests.template_binding_merge.common import ROOT, built, context, reidentify
from tests.transfer_signature.common import CASES, derive_case, golden_profile
from transfer_signature.evaluate import evaluate_transfer_signature
from transfer_signature.profile import validate_profile
from matcher.orchestrate import run_matcher


PRODUCER_ID = "cipherlens-current-v2-evaluation"
PRODUCER_VERSION = "0.1"
FAMILIES = tuple(CASES)
SUITES = (
    ("contract", "tests/contract_miner"),
    ("transfer_signature", "tests/transfer_signature"),
    ("binding_proposal", "tests/binding_proposal"),
    ("candidate_binding", "tests/candidate_binding"),
    ("trigger_interface", "tests/trigger_template_interface"),
    ("matcher", "tests/matcher"),
    ("merge", "tests/template_binding_merge"),
    ("execution_model", "tests/execution_model"),
    ("execution_pipeline", "tests/execution_pipeline"),
    ("execution_trace", "tests/execution_trace"),
    ("impact_bridge", "tests/impact_bridge"),
    ("pipeline_v2", "tests/pipeline_v2"),
    ("evaluation_evidence", "tests/evaluation_evidence"),
)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _deny_network(*_args: object, **_kwargs: object) -> None:
    raise RuntimeError("external network disabled by EvaluationProfile v0.1")


def _scope(**changes: bool) -> dict[str, bool]:
    value = {
        "current_v2": True, "real_campaign": False, "global_security": False,
        "confirmed_vulnerability": False, "upstream_acknowledged": False,
    }
    value.update(changes)
    return value


def _link(ref: ArtifactRef) -> dict[str, str]:
    return {"ref": ref.ref, "digest": ref.digest}


class EvaluationRun:
    def __init__(self, repo_root: Path, output_root: Path, git_revision: str) -> None:
        self.repo_root = repo_root.resolve()
        self.output_root = output_root
        self.git_revision = git_revision
        self.store = ArtifactStore(output_root)
        self.artifact_records: list[dict[str, Any]] = []
        self.test_run_records: list[dict[str, Any]] = []
        self.experiment_units: list[dict[str, Any]] = []
        self.metric_records: list[dict[str, Any]] = []
        self.metric_manifests: list[dict[str, Any]] = []
        self.claim_records: list[dict[str, Any]] = []
        self.gate_reports: list[dict[str, Any]] = []
        self.metric_items: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.metric_units: dict[str, list[dict[str, str]]] = defaultdict(list)
        self._links: dict[str, dict[str, str]] = {}
        self._primary_records: dict[tuple[str, str], dict[str, Any]] = {}
        self.policy_counters = {
            "real_codex_calls": 0, "glm_calls": 0, "openai_api_calls": 0,
            "external_network_calls": 0, "external_llm_cost": 0,
            "real_third_party_vulnerability_campaigns": 0,
        }

    def put_bytes(
        self, ref: str, payload: bytes, *, artifact_type: str,
        schema_version: str = "", media_type: str = "application/octet-stream",
        maturity: Iterable[ValidationMaturity] = (
            ValidationMaturity.SOURCE_PRESENT, ValidationMaturity.DIGEST_VERIFIED,
        ),
        execution_scope: str = "current-v2-evaluation", synthetic: bool = True,
        inventory: bool = True, notes: Iterable[str] = (),
    ) -> dict[str, str]:
        stored = self.store.put_raw(ref, payload, media_type=media_type)
        link = _link(stored)
        self._links[ref] = link
        if inventory and (ref, stored.digest) not in self._primary_records:
            record = build_artifact_record(
                artifact_ref=ref, artifact_digest=stored.digest,
                artifact_type=artifact_type, artifact_schema_version=schema_version,
                media_type=media_type, producer_id=PRODUCER_ID,
                producer_version=PRODUCER_VERSION, git_revision=self.git_revision,
                origin=EvidenceOrigin.CURRENT_V2,
                inventory_state=InventoryState.VERIFIED_PRESENT,
                validation_maturity=tuple(maturity), execution_scope=execution_scope,
                synthetic_or_real="SYNTHETIC" if synthetic else "REAL",
                public_disclosure_state="LOCAL_ONLY",
                source_location="artifacts/evaluation_v2", notes=tuple(notes),
            )
            self.artifact_records.append(record)
            self._primary_records[(ref, stored.digest)] = record
        return link

    def put_json(self, ref: str, value: Any, *, artifact_type: str, schema_version: str = "",
                 maturity: Iterable[ValidationMaturity] = (
                     ValidationMaturity.SOURCE_PRESENT, ValidationMaturity.DIGEST_VERIFIED,
                     ValidationMaturity.UNIT_VALIDATED,
                 ), inventory: bool = True, notes: Iterable[str] = ()) -> dict[str, str]:
        return self.put_bytes(
            ref, _json_bytes(value), artifact_type=artifact_type,
            schema_version=schema_version or str(value.get("schema_version", "")),
            media_type="application/json", maturity=maturity, inventory=inventory, notes=notes,
        )

    def put_eval_document(self, ref: str, value: Mapping[str, Any], *, artifact_type: str,
                          maturity: Iterable[ValidationMaturity]) -> dict[str, str]:
        validate_document_or_raise(value)
        return self.put_bytes(
            ref, canonical_bytes(value), artifact_type=artifact_type,
            schema_version=str(value["schema_version"]), media_type="application/json",
            maturity=maturity,
        )

    def put_file(self, relative: str, *, artifact_type: str = "test_definition") -> dict[str, str]:
        ref = f"repo-snapshot:{relative}"
        if ref in self._links:
            return self._links[ref]
        return self.put_bytes(
            ref, (self.repo_root / relative).read_bytes(), artifact_type=artifact_type,
            media_type="text/x-python" if relative.endswith(".py") else "application/yaml",
            execution_scope="repository-snapshot",
        )

    def add_experiment(
        self, *, rq: str, unit_type: str, family: str, scenario: str,
        input_refs: Iterable[Mapping[str, str]], output_refs: Iterable[Mapping[str, str]],
        completion_status: str = "COMPLETE", notes: Iterable[str] = (),
    ) -> tuple[dict[str, Any], dict[str, str]]:
        unit = build_experiment_unit(
            research_question_refs=[rq], unit_type=unit_type,
            target_scope={"library": "synthetic", "version": "golden-v0.1", "build_profile": "local-controlled"},
            input_refs=input_refs, attempt_refs=[], output_refs=output_refs,
            inclusion_status="INCLUDED", completion_status=completion_status,
            origin=EvidenceOrigin.CURRENT_V2,
            notes=[f"family={family}", f"scenario={scenario}", *notes],
        )
        ref = f"experiment-unit:{unit['experiment_unit_id']}"
        link = self.put_eval_document(
            ref, unit, artifact_type="experiment_unit",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.UNIT_VALIDATED),
        )
        self.experiment_units.append(unit)
        return unit, link

    def add_metric_item(self, metric_name: str, label: str, payload: Mapping[str, Any], *,
                        artifact_type: str, status: str) -> dict[str, str]:
        safe = label.replace("/", "_").replace(":", "_")
        link = self.put_json(
            f"metric-observations/{metric_name}/{safe}.json", payload,
            artifact_type=artifact_type, inventory=False,
        )
        self.metric_items[metric_name].append({
            **link, "artifact_type": artifact_type, "origin": EvidenceOrigin.CURRENT_V2.value,
            "attributes": {"status": status},
        })
        return link

    def add_metric(self, name: str, definition: Mapping[str, Any] | None = None) -> dict[str, Any]:
        metric_definition = dict(definition or INITIAL_METRIC_REGISTRY[name])
        definition_ref = f"metric-definition:{metric_definition['metric_definition_id']}"
        self.put_eval_document(
            definition_ref, metric_definition, artifact_type="metric_definition",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
        )
        manifest = build_population_manifest(
            metric_definition, self.metric_items[name], origin=EvidenceOrigin.CURRENT_V2, complete=True,
        )
        manifest_ref = f"metric-population:{manifest['population_manifest_id']}"
        self.put_eval_document(
            manifest_ref, manifest, artifact_type="metric_population_manifest",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
        )
        record = evaluate_metric(
            metric_definition, manifest, resolver=self.store.verify,
            git_revision=self.git_revision, experiment_unit_refs=self.metric_units[name],
            producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
        )
        record_ref = f"metric-record:{record['metric_record_id']}"
        self.put_eval_document(
            record_ref, record, artifact_type="metric_record",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.UNIT_VALIDATED),
        )
        self.metric_manifests.append(manifest)
        self.metric_records.append(record)
        return record


def metric_definition(name: str, rq: str, population_unit: str, artifact_type: str,
                      *, status: str | None = None, ratio: bool = False) -> dict[str, Any]:
    all_rule = {"kind": "ALL", "predicates": []}
    none_rule = {"kind": "NONE", "predicates": []}
    filter_rule = {"kind": "FILTER", "predicates": [{"field": "attributes.status", "comparator": "EQ", "value": status}]}
    value = {
        "schema_version": SCHEMA_VERSIONS["metric_definition"],
        "metric_definition_id": "pending", "metric_name": name,
        "definition_version": "0.1", "research_question_refs": [rq],
        "population_unit": population_unit, "selection_rule": all_rule,
        "numerator_rule": filter_rule if status is not None else all_rule,
        "denominator_rule": all_rule if ratio else none_rule,
        "aggregation_rule": "RATIO" if ratio else "COUNT",
        "required_artifact_types": [artifact_type],
        "allowed_origins": [EvidenceOrigin.CURRENT_V2.value],
        "allowed_claim_levels": [
            ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM.value,
            ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM.value,
        ],
        "presentation_rule": {
            "format": "EXACT_RATIO" if ratio else "INTEGER", "scale": 1, "decimals": 0,
        },
        "forbidden_interpretations": [
            "Synthetic evaluation is not a real-library success rate",
            "A test or witness count is not a vulnerability confirmation",
        ],
    }
    result = identify(value)
    validate_document_or_raise(result)
    return result


def evaluation_profile(git_revision: str) -> dict[str, Any]:
    try:
        compiler_profile = subprocess.check_output(
            ["cc", "--version"], text=True, stderr=subprocess.STDOUT,
        ).splitlines()[0]
    except (FileNotFoundError, subprocess.CalledProcessError, IndexError):
        compiler_profile = "cc-unavailable"
    semantic = {
        "schema_version": "cipherlens.evaluation_profile.v0.1",
        "git_revision": git_revision,
        "evaluation_scope": ["RQ-ENG", "RQ1", "RQ2", "RQ3"],
        "python_version": platform.python_version(),
        "os_logical_profile": f"{platform.system().lower()}-{platform.machine().lower()}",
        "compiler_profile": compiler_profile,
        "network_policy": "DISABLED",
        "real_provider_policy": "DISABLED",
        "real_third_party_campaign": "DISABLED",
        "selected_suites": [name for name, _ in SUITES],
        "selected_experiments": ["RQ1_STRUCTURE", "RQ2_MIGRATION", "RQ3_VALIDATION"],
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    return {**semantic, "evaluation_id": f"evaluation:{digest}"}


def run_formal_tests(run: EvaluationRun, profile: Mapping[str, Any]) -> dict[str, Any]:
    all_identities: dict[str, list[str]] = {key: [] for key in ("passed", "failed", "skipped", "xfailed", "errors")}
    suite_summaries: list[dict[str, Any]] = []
    env = dict(os.environ)
    env.update({
        "CIPHERLENS_NETWORK_POLICY": "DISABLED",
        "CIPHERLENS_REAL_PROVIDER_POLICY": "DISABLED",
        "CIPHERLENS_REAL_CAMPAIGN_POLICY": "DISABLED",
    })
    for suite_name, start_dir in SUITES:
        definitions = sorted((run.repo_root / start_dir).glob("test_*.py"))
        definition_refs = [run.put_file(path.relative_to(run.repo_root).as_posix()) for path in definitions]
        command = [
            "python3", "-m", "evaluation_evidence.test_executor", "--suite", suite_name,
            "--start-dir", start_dir, "--pattern", "test_*.py", "--deny-network",
        ]
        completed = subprocess.run(
            command, cwd=run.repo_root, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        try:
            structured = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"formal suite {suite_name} did not emit structured output") from exc
        counts = structured["counts"]
        identities = structured["identities"]
        record = record_test_run(
            run.store, ref_prefix=f"runs/{suite_name}", git_revision=run.git_revision,
            command=command, test_scope=suite_name, test_definition_refs=definition_refs,
            counts=counts, stdout=completed.stdout, stderr=completed.stderr,
            result_identities=identities,
            working_profile={
                "profile": "repository-root", "network_guard": "deny-socket-connect",
                "provider_policy": "disabled", "campaign_policy": "disabled",
            },
            environment_profile={
                "python_version": profile["python_version"],
                "os_logical_profile": profile["os_logical_profile"],
                "network_policy": "DISABLED", "real_provider_policy": "DISABLED",
            },
            producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
        )
        ref = f"test-run:{record['test_run_id']}"
        link = run.put_eval_document(
            ref, record, artifact_type="test_run_record",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.TEST_RUN_RECORDED),
        )
        run.test_run_records.append(record)
        suite_summary = {
            "suite": suite_name, "return_code": completed.returncode,
            "discovered": structured["discovered"], "counts": counts,
            "test_run_ref": link,
        }
        suite_summaries.append(suite_summary)
        run.add_metric_item(
            "recorded_test_run_count", suite_name, suite_summary,
            artifact_type="test_run_record", status="RECORDED",
        )
        for outcome, values in identities.items():
            all_identities[outcome].extend(values)
            for identity in values:
                run.add_metric_item(
                    "formal_test_population", identity, {"test_id": identity, "suite": suite_name, "outcome": outcome.upper()},
                    artifact_type="formal_test_case_result", status=outcome.upper(),
                )
        for path, definition_ref in zip(definitions, definition_refs):
            run.metric_items["test_definition_count"].append({
                **definition_ref, "artifact_type": "test_definition", "origin": EvidenceOrigin.CURRENT_V2.value,
                "attributes": {"status": "DEFINED"},
            })
        if completed.returncode != 0 or counts["failed"] or counts["errors"]:
            break
    return {"suites": suite_summaries, "identities": {key: sorted(value) for key, value in all_identities.items()}}


def _rq1_validate(gated: Any, merge: dict[str, Any], *, mutate_source: bool = False) -> tuple[dict[str, Any], Any]:
    rendered = render_base_source(merge, ROOT)
    completed = programmatic_complete(merge, rendered.source_bytes, rendered.source_map, rendered.bound_source, ROOT)
    source = completed.source_bytes
    if mutate_source:
        changed = bytearray(source)
        changed[0] = (changed[0] + 1) % 255
        source = bytes(changed)
    validation = validate_merged_source(
        ValidationContext(gated, merge, source, completed.source_map, completed.bound_source)
    )
    return validation, completed


def run_rq1(run: EvaluationRun) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    baseline: dict[str, tuple[Any, dict[str, Any], Any]] = {}
    for family in FAMILIES:
        gated, merge, _ = built(family)
        validation, completed = _rq1_validate(gated, merge)
        baseline[family] = (gated, merge, completed)
        scenarios = [("required_slots_fully_bound", merge, False, validation)]
        for slot in gated.template_manifest["slots"]:
            run.add_metric_item(
                "stable_slot_count", f"{family}-{slot['slot_ref']}",
                {"family": family, "slot_ref": slot["slot_ref"], "required": slot["required"]},
                artifact_type="trigger_template", status="STABLE",
            )
        run.add_metric_item(
            "trigger_template_count", family, {"family": family, "template_ref": gated.template_manifest["trigger_template_ref"]},
            artifact_type="trigger_template", status="VALIDATED",
        )
        for index, obligation in enumerate(merge["structural_obligations"]):
            run.add_metric_item(
                "structural_obligation_count", f"{family}-{index}",
                {"family": family, "obligation": obligation}, artifact_type="trigger_template", status="PRESENT",
            )
        for scenario, scenario_merge, mutate_source, preset in scenarios:
            results.append(_record_rq1_scenario(run, family, scenario, gated, scenario_merge, mutate_source, preset))

    gated, merge, _ = built("mbedtls_poc_0020")
    mutations: list[tuple[str, dict[str, Any], bool]] = []
    changed = deepcopy(merge)
    required = {item["slot_ref"] for item in gated.template_manifest["slots"] if item["required"]}
    victim = next(item for item in changed["slot_bindings"] if item["template_slot_ref"] in required)
    changed["slot_bindings"].remove(victim); mutations.append(("missing_required_slot", reidentify(changed), False))
    changed = deepcopy(merge)
    next(item for item in changed["structural_obligations"] if item["obligation_type"] == "OPERATION_SEQUENCE_PRESERVED")["ordered_refs"].reverse()
    mutations.append(("operation_reorder", reidentify(changed), False))
    changed = deepcopy(merge)
    obligation = next(item for item in changed["structural_obligations"] if item["obligation_type"] == "INTERVENTION_PHASE_PRESERVED")
    obligation["typed_refs"][0] = obligation["typed_refs"][0] + ":MOVED"
    mutations.append(("intervention_moved", reidentify(changed), False))
    changed = deepcopy(merge); del changed["observation_capture_bindings"][0]
    mutations.append(("observation_removed", reidentify(changed), False))
    changed = deepcopy(merge); changed["identity_realizations"][0]["storage_ref"] = "storage:broken"
    mutations.append(("identity_broken", reidentify(changed), False))
    changed = deepcopy(merge); changed["correlation_realizations"][0]["correlation_kind"] = "SAME_STEP"
    mutations.append(("correlation_broken", reidentify(changed), False))
    mutations.append(("protected_region_mutation", merge, True))
    for scenario, candidate, mutate_source in mutations:
        validation, _ = _rq1_validate(gated, candidate, mutate_source=mutate_source)
        results.append(_record_rq1_scenario(run, "mbedtls_poc_0020", scenario, gated, candidate, mutate_source, validation))
    return results


def _record_rq1_scenario(run: EvaluationRun, family: str, scenario: str, gated: Any,
                         merge: dict[str, Any], mutate_source: bool, validation: dict[str, Any]) -> dict[str, Any]:
    required = {item["slot_ref"] for item in gated.template_manifest["slots"] if item["required"]}
    bound = {item["template_slot_ref"] for item in merge["slot_bindings"]}
    result = {
        "schema_version": "cipherlens.rq1_structure_result.v0.1", "family": family,
        "scenario": scenario, "validation_status": validation["status"],
        "validation_routing": validation["routing"], "required_slots": [
            {"slot_ref": ref, "status": "FILLED" if ref in bound else "MISSING"} for ref in sorted(required)
        ],
        "merge_slots": [
            {"slot_ref": item["slot_ref"], "status": "FILLED" if item["slot_ref"] in bound else "MISSING"}
            for item in gated.template_manifest["slots"]
        ],
        "protected_regions": [{"region_ref": "protected:source", "status": "MUTATED" if mutate_source else "PRESERVED"}],
        "check_results": validation["check_results"],
    }
    output = run.put_json(
        f"experiments/rq1/{family}/{scenario}.json", result,
        artifact_type="merge_validation", schema_version=result["schema_version"],
        maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.UNIT_VALIDATED, ValidationMaturity.SYNTHETIC_E2E_VALIDATED),
    )
    unit, unit_link = run.add_experiment(
        rq="RQ1", unit_type="STRUCTURE_PRESERVATION", family=family, scenario=scenario,
        input_refs=[], output_refs=[output],
        notes=["Result produced by deterministic merge validation"],
    )
    for item in result["required_slots"]:
        run.add_metric_item("required_slot_coverage", f"{family}-{scenario}-{item['slot_ref']}", item,
                            artifact_type="merge_validation", status=item["status"])
    for item in result["merge_slots"]:
        run.add_metric_item("merge_slot_coverage", f"{family}-{scenario}-{item['slot_ref']}", item,
                            artifact_type="merge_validation", status=item["status"])
    for item in result["protected_regions"]:
        run.add_metric_item("protected_region_preservation_rate", f"{family}-{scenario}", item,
                            artifact_type="merge_validation", status=item["status"])
    for name in ("required_slot_coverage", "merge_slot_coverage", "protected_region_preservation_rate"):
        run.metric_units[name].append(unit_link)
    return {"unit": unit, "result": result, "artifact": output}


def run_rq2(run: EvaluationRun) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for family in FAMILIES:
        signature, contract, _ = derive_case(family)
        ts_link = run.put_json(f"experiments/rq2/{family}/signature.json", signature, artifact_type="transfer_signature")
        run.add_metric_item("transfer_signature_count", family, {"family": family, "signature_id": signature["signature_id"]}, artifact_type="transfer_signature", status="DERIVED")
        for label in ("eligible", "ineligible", "indeterminate"):
            profile = golden_profile(family, label)
            evaluation = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
            results.append(_record_rq2_evaluation(run, family, label, ts_link, profile, evaluation, invoke_matcher=label == "eligible"))

    signature, contract, _ = derive_case("mbedtls_poc_0020")
    base = golden_profile("mbedtls_poc_0020", "eligible")
    variants: list[tuple[str, dict[str, Any]]] = []
    changed = deepcopy(base); next(item for item in changed["facts"] if item["fact_type"] == "operation_role")["parameters"]["role"] = "VERIFY"
    variants.append(("incompatible_parameters", changed))
    for epistemic in ("INFERRED", "PROPOSED"):
        changed = deepcopy(base); next(item for item in changed["facts"] if item["fact_type"] == "operation_role")["epistemic_status"] = epistemic
        variants.append((f"{epistemic.lower()}_fact", changed))
    changed = deepcopy(base); channel = next(item for item in changed["facts"] if item["fact_type"] == "observable_channel"); channel["assertion"] = "FALSE"
    variants.append(("missing_observability", changed))
    for label, profile in variants:
        evaluation = evaluate_transfer_signature(signature, profile, contract, repo_root=ROOT)
        results.append(_record_rq2_evaluation(run, "mbedtls_poc_0020", label, {}, profile, evaluation, invoke_matcher=False))

    signature4, contract4, _ = derive_case("mbedtls_poc_0004")
    wrong_subject = golden_profile("mbedtls_poc_0004", "eligible")
    operation = next(item for item in wrong_subject["facts"] if item["fact_type"] == "operation_role")
    operation["subject_ref"] = "SYNTHETIC_CIPHER_INPUT"
    wrong_subject_evaluation = evaluate_transfer_signature(signature4, wrong_subject, contract4, repo_root=ROOT)
    results.append(_record_rq2_evaluation(
        run, "mbedtls_poc_0004", "wrong_subject", {}, wrong_subject,
        wrong_subject_evaluation, invoke_matcher=False,
    ))

    conflict = deepcopy(base); opposite = deepcopy(conflict["facts"][0]); opposite["fact_id"] = "F_CONFLICTING_FACT"; opposite["assertion"] = "FALSE" if opposite["assertion"] == "TRUE" else "TRUE"; conflict["facts"].append(opposite)
    errors = validate_profile(conflict, ROOT)
    rejection = {"schema_version": "cipherlens.rq2_profile_rejection.v0.1", "scenario": "conflicting_verified_facts", "errors": errors, "eligibility": "PROFILE_REJECTED", "matcher_invoked": False}
    output = run.put_json("experiments/rq2/mbedtls_poc_0020/conflicting_verified_facts.json", rejection, artifact_type="ts_evaluation")
    _, unit_link = run.add_experiment(rq="RQ2", unit_type="CONTRACT_GUIDED_MIGRATION", family="mbedtls_poc_0020", scenario="conflicting_verified_facts", input_refs=[], output_refs=[output], notes=["Conflicting VERIFIED facts are rejected before eligibility"])
    run.add_metric_item("eligibility_evaluation_count", "conflicting_verified_facts", rejection, artifact_type="ts_evaluation", status="PROFILE_REJECTED")
    run.metric_units["eligibility_evaluation_count"].append(unit_link)
    results.append({"result": rejection, "artifact": output})

    signature5, contract5, _ = derive_case("mbedtls_poc_0005")
    profile5 = golden_profile("mbedtls_poc_0005", "eligible")
    constraint = next(item for item in signature5["required_capabilities"] if item["type"] == "supports_execution_shape")
    constraint["parameters"]["continuity"] = "multi_subject"
    fact = next(item for item in profile5["facts"] if item["fact_type"] == "execution_shape")
    fact["parameters"]["continuity"] = "multi_subject"
    fact["parameters"]["participant_refs"] = ["SYNTHETIC_UPDATE", "SYNTHETIC_STATE_SURFACE", "SYNTHETIC_UPDATE"]
    evaluation5 = evaluate_transfer_signature(signature5, profile5, contract5, repo_root=ROOT)
    results.append(_record_rq2_evaluation(run, "mbedtls_poc_0005", "multi_subject_surface", {}, profile5, evaluation5, invoke_matcher=False))
    return results


def _record_rq2_evaluation(run: EvaluationRun, family: str, label: str,
                           ts_link: Mapping[str, str], profile: Mapping[str, Any],
                           evaluation: Mapping[str, Any], *, invoke_matcher: bool) -> dict[str, Any]:
    profile_link = run.put_json(f"experiments/rq2/{family}/{label}.profile.json", profile, artifact_type="target_semantic_profile")
    evaluation_link = run.put_json(
        f"experiments/rq2/{family}/{label}.evaluation.json", evaluation,
        artifact_type="ts_evaluation",
        maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.UNIT_VALIDATED, ValidationMaturity.GOLDEN_VALIDATED),
    )
    routing: dict[str, Any] = {
        "schema_version": "cipherlens.rq2_hard_filter_result.v0.1", "family": family,
        "scenario": label, "eligibility": evaluation["eligibility"],
        "matcher_invoked": False, "ranking_invoked": False,
        "llm_override_allowed": False, "hard_filter_enforced": evaluation["eligibility"] != "ELIGIBLE",
    }
    output_refs = [evaluation_link]
    matcher_result = None
    if invoke_matcher:
        request, replay, backend = case_request(family)
        matcher_result = run_matcher(request)
        routing.update({
            "matcher_invoked": True, "ranking_invoked": True,
            "hard_filter_enforced": False, "matcher_outcome": matcher_result.outcome.value,
            "replay_invocations": replay.invocation_count,
            "network_calls": backend.network_call_count,
        })
        run.policy_counters["external_network_calls"] += backend.network_call_count
        trace_link = run.put_json(f"experiments/rq2/{family}/{label}.matcher-trace.json", matcher_result.trace.semantic_core, artifact_type="matcher_trace")
        output_refs.append(trace_link)
        for index, record in enumerate(matcher_result.trace.semantic_core["retrieval_records"]):
            run.add_metric_item("candidate_surface_count", f"{family}-{label}-{index}", record, artifact_type="matcher_trace", status="RECALLED")
        if matcher_result.candidate_binding is not None:
            binding_link = run.put_bytes(
                f"experiments/rq2/{family}/{label}.candidate-binding.yaml",
                canonical_candidate_binding_bytes(matcher_result.candidate_binding), artifact_type="candidate_binding",
                schema_version=matcher_result.candidate_binding["schema_version"], media_type="application/yaml",
                maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.GOLDEN_VALIDATED),
            )
            validation_link = run.put_bytes(
                f"experiments/rq2/{family}/{label}.binding-validation.yaml",
                canonical_validation_bytes(matcher_result.candidate_binding_validation), artifact_type="candidate_binding_validation",
                schema_version=matcher_result.candidate_binding_validation["schema_version"], media_type="application/yaml",
                maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.GOLDEN_VALIDATED),
            )
            output_refs.extend([binding_link, validation_link])
            run.metric_items["candidate_binding_count"].append({**binding_link, "artifact_type": "candidate_binding", "origin": "CURRENT_V2", "attributes": {"status": "BUILT"}})
            run.metric_items["valid_binding_count"].append({**validation_link, "artifact_type": "candidate_binding_validation", "origin": "CURRENT_V2", "attributes": {"status": matcher_result.candidate_binding_validation["status"]}})
    routing_link = run.put_json(f"experiments/rq2/{family}/{label}.routing.json", routing, artifact_type="hard_filter_result")
    output_refs.append(routing_link)
    _, unit_link = run.add_experiment(
        rq="RQ2", unit_type="CONTRACT_GUIDED_MIGRATION", family=family, scenario=label,
        input_refs=[item for item in (ts_link, profile_link) if item], output_refs=output_refs,
        notes=["TS eligibility is deterministic and precedes matcher/ranking"],
    )
    run.add_metric_item("target_profile_count", f"{family}-{label}", profile, artifact_type="target_semantic_profile", status="PROFILED")
    run.metric_items["eligibility_evaluation_count"].append({**evaluation_link, "artifact_type": "ts_evaluation", "origin": "CURRENT_V2", "attributes": {"status": evaluation["eligibility"]}})
    if evaluation["eligibility"] == "INELIGIBLE":
        run.metric_items["ineligible_filter_count"].append({**evaluation_link, "artifact_type": "ts_evaluation", "origin": "CURRENT_V2", "attributes": {"status": "INELIGIBLE"}})
    if evaluation["eligibility"] == "INDETERMINATE":
        run.metric_items["indeterminate_evidence_gap_count"].append({**evaluation_link, "artifact_type": "ts_evaluation", "origin": "CURRENT_V2", "attributes": {"status": "INDETERMINATE"}})
    for name in ("target_profile_count", "eligibility_evaluation_count", "candidate_surface_count", "candidate_binding_count", "valid_binding_count", "ineligible_filter_count", "indeterminate_evidence_gap_count"):
        run.metric_units[name].append(unit_link)
    return {"evaluation": dict(evaluation), "routing": routing, "artifact": evaluation_link, "matcher": matcher_result}


def run_rq3(run: EvaluationRun) -> list[dict[str, Any]]:
    specifications = (
        ("mbedtls_poc_0020", "satisfied", {}, {}),
        ("mbedtls_poc_0020", "violated", {"CONSUMED_LENGTH": 7}, {}),
        ("mbedtls_poc_0020", "unknown_guard_rejected", {"PARSE_OUTCOME": "reject"}, {}),
        ("mbedtls_poc_0004", "satisfied", {}, {}),
        ("mbedtls_poc_0004", "violated_output", {"OUTPUT_LENGTH_AFTER": 4}, {}),
        ("mbedtls_poc_0004", "unknown_missing_correlation", {}, {"OUTPUT_LENGTH_BEFORE": "ACQUISITION_FAILED", "OUTPUT_LENGTH_AFTER": "ACQUISITION_FAILED"}),
        ("mbedtls_poc_0005", "satisfied", {}, {"REUSE_FATAL_EVENT": "OBSERVED_ABSENCE"}),
        ("mbedtls_poc_0005", "violated_state", {"STORED_LENGTH_AFTER_ZERO": 4}, {"REUSE_FATAL_EVENT": "NOT_REACHED"}),
        ("mbedtls_poc_0005", "unknown_fatal_channel", {}, {"REUSE_FATAL_EVENT": "CHANNEL_UNAVAILABLE"}),
    )
    results: list[dict[str, Any]] = []
    for family, scenario, values, statuses in specifications:
        data = chain(family, values=values, statuses=statuses)
        output_refs: list[dict[str, str]] = []
        documents = (
            ("witness", data["witness"], "execution_witness"),
            ("trace", data["trace"], "structured_execution_trace"),
            ("projection", data["projection"], "execution_projection"),
            ("verdict", data["verdict"], "execution_verdict"),
        )
        stored: dict[str, dict[str, str]] = {}
        for label, document, artifact_type in documents:
            link = run.put_bytes(
                f"experiments/rq3/{family}/{scenario}.{label}.json",
                execution_canonical_bytes(document), artifact_type=artifact_type,
                schema_version=document["schema_version"], media_type="application/json",
                maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.GOLDEN_VALIDATED, ValidationMaturity.SYNTHETIC_E2E_VALIDATED),
            )
            stored[label] = link; output_refs.append(link)
        relation_links: list[dict[str, str]] = []
        for index, evaluation in enumerate(data["evaluations"]):
            link = run.put_bytes(
                f"experiments/rq3/{family}/{scenario}.relation-{index}.json",
                execution_canonical_bytes(evaluation), artifact_type="relation_evaluation",
                schema_version=evaluation["schema_version"], media_type="application/json",
                maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.GOLDEN_VALIDATED),
            )
            relation_links.append(link); output_refs.append(link)
        closure_link = None
        if data["verdict"]["verdict"] == "UNKNOWN":
            non_eval = [item for item in data["evaluations"] if item["result"] == "NOT_EVALUABLE"]
            closure_reason_map = {
                "PRECONDITION_NOT_MET": "RELATION_PRECONDITION_NOT_MET",
                "INVALID_VALUE": "RELATION_NOT_EVALUABLE",
                "IDENTITY_MISMATCH": "INCOMPLETE_CORRELATION",
                "CORRELATION_MISMATCH": "INCOMPLETE_CORRELATION",
            }
            reasons = [closure_reason_map.get(item["reason_code"], item["reason_code"]) for item in non_eval]
            missing = [ref for item in non_eval for ref in item.get("missing_observable_refs", [])]
            closure = build_unknown_closure(data["verdict"], reason_codes=reasons, missing_evidence=missing or ["required-observable"])
            closure_link = run.put_bytes(
                f"experiments/rq3/{family}/{scenario}.closure.json", execution_canonical_bytes(closure),
                artifact_type="execution_closure", schema_version=closure["schema_version"], media_type="application/json",
                maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED, ValidationMaturity.UNIT_VALIDATED),
            )
            output_refs.append(closure_link)
        _, unit_link = run.add_experiment(
            rq="RQ3", unit_type="MULTI_EVIDENCE_VALIDATION", family=family, scenario=scenario,
            input_refs=[], output_refs=output_refs,
            notes=["Synthetic/golden witness; not a real vulnerability campaign"],
        )
        run.metric_items["execution_witness_count"].append({**stored["witness"], "artifact_type": "execution_witness", "origin": "CURRENT_V2", "attributes": {"status": data["witness"]["status"]}})
        run.metric_items["structured_trace_count"].append({**stored["trace"], "artifact_type": "structured_execution_trace", "origin": "CURRENT_V2", "attributes": {"status": "STRUCTURED"}})
        for link, evaluation in zip(relation_links, data["evaluations"]):
            run.metric_items["relation_evaluation_count"].append({**link, "artifact_type": "relation_evaluation", "origin": "CURRENT_V2", "attributes": {"status": evaluation["result"]}})
        verdict_name = {"SATISFIED": "satisfied_witness_count", "VIOLATED": "violated_witness_count", "UNKNOWN": "unknown_witness_count"}[data["verdict"]["verdict"]]
        run.metric_items[verdict_name].append({**stored["verdict"], "artifact_type": "execution_verdict", "origin": "CURRENT_V2", "attributes": {"status": data["verdict"]["verdict"]}})
        if closure_link:
            run.metric_items["unknown_closure_route_count"].append({**closure_link, "artifact_type": "execution_closure", "origin": "CURRENT_V2", "attributes": {"status": "ROUTED"}})
        for name in ("execution_witness_count", "structured_trace_count", "relation_evaluation_count", "satisfied_witness_count", "violated_witness_count", "unknown_witness_count", "unknown_closure_route_count"):
            run.metric_units[name].append(unit_link)
        results.append({"family": family, "scenario": scenario, "verdict": data["verdict"]["verdict"], "artifact": stored["verdict"], "unit_ref": unit_link})

    results.extend(run_rq3_ablation(run))
    return results


def run_rq3_ablation(run: EvaluationRun) -> list[dict[str, Any]]:
    cases: list[tuple[str, dict[str, Any]]] = []
    sanitizer_records, sanitizer_events = sanitizer_evidence("raw:synthetic-sanitizer", b"ERROR: AddressSanitizer: synthetic fixture")
    unknown = chain(statuses={"CONSUMED_LENGTH": "ACQUISITION_FAILED"})
    cases.append(("sanitizer_present", {"process_evidence": sanitizer_events, "legacy": import_legacy_result({"sanitizer": "present"}), "contract_verdict": unknown["verdict"]["verdict"]}))
    cases.append(("crash", {"legacy": import_legacy_result({"verdict": "crash"}), "contract_verdict": unknown["verdict"]["verdict"]}))
    return_only = chain("mbedtls_poc_0004", statuses={"OUTPUT_LENGTH_BEFORE": "ACQUISITION_FAILED", "OUTPUT_LENGTH_AFTER": "ACQUISITION_FAILED"})
    cases.append(("return_code_only", {"observed_return": "reject", "contract_verdict": return_only["verdict"]["verdict"]}))
    compile_data = chain(); failed_build = built_record(compile_data["build_spec"], result="COMPILE_FAILED")
    cases.append(("compile_failure", {"attempt_outcome": attempt_outcome(failed_build, None), "execution_verdict": None}))
    missing = chain(statuses={"CONSUMED_LENGTH": "NOT_REACHED"})
    cases.append(("missing_observable", {"contract_verdict": missing["verdict"]["verdict"]}))
    partial = chain(partial=True)
    cases.append(("partial_witness", {"witness_status": partial["witness"]["status"], "contract_verdict": partial["verdict"]["verdict"]}))
    conflict = chain(statuses={"CONSUMED_LENGTH": "CONFLICTING_EVIDENCE"})
    cases.append(("conflicting_evidence", {"contract_verdict": conflict["verdict"]["verdict"]}))
    results: list[dict[str, Any]] = []
    for scenario, actual in cases:
        document = {
            "schema_version": "cipherlens.rq3_single_signal_ablation.v0.1",
            "scenario": scenario, "ablation_scope": "SYNTHETIC_CONTROLLED",
            "actual": actual,
            "interpretation": "Process or partial evidence cannot independently decide Contract.P",
        }
        output = run.put_json(f"experiments/rq3/ablation/{scenario}.json", document, artifact_type="controlled_ablation")
        unit, unit_link = run.add_experiment(
            rq="RQ3", unit_type="SINGLE_SIGNAL_VS_CONTRACT", family="controlled_ablation",
            scenario=scenario, input_refs=[], output_refs=[output],
            notes=["No real-world false-positive claim is supported"],
        )
        results.append({"family": "controlled_ablation", "scenario": scenario, "artifact": output, "unit": unit, "unit_ref": unit_link})
    return results


def build_metrics(run: EvaluationRun, formal: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    formal_population = [deepcopy(item) for item in run.metric_items["formal_test_population"]]
    for status in ("passed", "failed", "skipped", "xfailed", "errors"):
        name = f"formal_test_{status}_count"
        run.metric_items[name] = [deepcopy(item) for item in formal_population]
        metrics[name] = run.add_metric(name, metric_definition(name, "RQ-ENG", "FORMAL_TEST_CASE", "formal_test_case_result", status=status.upper()))
    run.metric_items["formal_test_population_count"] = [deepcopy(item) for item in formal_population]
    metrics["formal_test_population_count"] = run.add_metric(
        "formal_test_population_count",
        metric_definition("formal_test_population_count", "RQ-ENG", "FORMAL_TEST_CASE", "formal_test_case_result"),
    )
    for name in ("test_definition_count", "recorded_test_run_count"):
        metrics[name] = run.add_metric(name)
    rq1 = (
        "trigger_template_count", "stable_slot_count", "required_slot_coverage",
        "structural_obligation_count", "merge_slot_coverage", "protected_region_preservation_rate",
    )
    rq2 = (
        "transfer_signature_count", "target_profile_count", "eligibility_evaluation_count",
        "candidate_surface_count", "candidate_binding_count", "valid_binding_count",
        "ineligible_filter_count", "indeterminate_evidence_gap_count",
    )
    rq3 = (
        "execution_witness_count", "structured_trace_count", "relation_evaluation_count",
        "satisfied_witness_count", "violated_witness_count", "unknown_witness_count",
        "unknown_closure_route_count",
    )
    for name in (*rq1, *rq2, *rq3):
        metrics[name] = run.add_metric(name)
    return metrics


def build_claims_and_exports(run: EvaluationRun, metrics: Mapping[str, dict[str, Any]],
                             rq1: list[dict[str, Any]], rq2: list[dict[str, Any]],
                             rq3: list[dict[str, Any]], profile_link: Mapping[str, str]) -> dict[str, Any]:
    evidence = {
        "C1": next(record for record in run.artifact_records if record["artifact_type"] == "test_run_record"),
        "C2": run._primary_records[(rq1[0]["artifact"]["ref"], rq1[0]["artifact"]["digest"])],
        "C3": run._primary_records[(rq2[0]["artifact"]["ref"], rq2[0]["artifact"]["digest"])],
        "C4": next(record for record in run.artifact_records if record["artifact_type"] == "candidate_binding"),
        "C5": next(record for record in run.artifact_records if record["artifact_type"] == "execution_verdict"),
    }
    specs = (
        ("C1", "CipherLens v2 核心模块通过本轮正式回归验证。", ClaimTaxonomy.ENGINEERING_VALIDATION_CLAIM, ["4.3"], ["engineering-validation"], ["formal_test_population_count", "formal_test_passed_count", "formal_test_failed_count"]),
        ("C2", "结构保持模板在受控实验中保持 required slot / operation / intervention / observation obligations。", ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM, ["4.4"], ["rq1-synthetic"], ["required_slot_coverage", "merge_slot_coverage", "protected_region_preservation_rate"]),
        ("C3", "Transfer Signature 对不满足迁移资格的目标执行确定性 hard filtering。", ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM, ["4.5"], ["rq2-synthetic"], ["eligibility_evaluation_count", "ineligible_filter_count", "indeterminate_evidence_gap_count"]),
        ("C4", "CandidateBinding 通过完整 binding tuple 与 deterministic validation 约束具体迁移。", ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM, ["4.5"], ["rq2-synthetic"], ["candidate_binding_count", "valid_binding_count"]),
        ("C5", "Contract-driven evaluator 能区分 SATISFIED / VIOLATED / UNKNOWN 并避免以单一 crash/sanitizer 信号直接下结论。", ClaimTaxonomy.PIPELINE_VALIDATION_CLAIM, ["4.6", "4.7"], ["rq3-synthetic"], ["satisfied_witness_count", "violated_witness_count", "unknown_witness_count"]),
    )
    for claim_id, statement, taxonomy, sections, ppt, metric_names in specs:
        record = evidence[claim_id]
        link = {"ref": record["artifact_ref"], "digest": record["artifact_digest"]}
        claim = build_claim_record(
            claim_taxonomy=taxonomy, statement=statement, scope=_scope(), evidence_refs=[link],
            metric_refs=[metric_link(metrics[name]) for name in metric_names],
            requested_report_sections=sections, requested_ppt_usage=ppt,
            git_revision=run.git_revision, producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
        )
        run.claim_records.append(claim)
        run.put_eval_document(
            f"claim:{claim['claim_id']}", claim, artifact_type="claim_record",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
        )
    c6 = build_claim_record(
        claim_taxonomy=ClaimTaxonomy.CURRENT_CAMPAIGN_RESULT_CLAIM,
        statement="当前 synthetic evaluation 证明 CipherLens v2 已发现 X 个真实漏洞。",
        scope=_scope(real_campaign=True, confirmed_vulnerability=True), evidence_refs=[],
        requested_report_sections=["4.8"], requested_ppt_usage=["real-results-wall"],
        git_revision=run.git_revision, producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
    )
    run.claim_records.append(c6)
    run.put_eval_document(
        f"claim:{c6['claim_id']}", c6, artifact_type="claim_record",
        maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
    )
    ledger = build_evidence_ledger(
        git_revision=run.git_revision, artifact_records=run.artifact_records,
        test_run_records=run.test_run_records, experiment_units=run.experiment_units,
        metric_records=run.metric_records, finding_records=[], claim_records=run.claim_records,
        producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
    )
    ledger_link = run.put_eval_document(
        f"evaluation-ledger:{ledger['ledger_id']}", ledger, artifact_type="evaluation_evidence_ledger",
        maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
    )
    for claim in run.claim_records:
        report = evaluate_claim(
            claim, artifact_records=run.artifact_records, metric_records=run.metric_records,
            findings=[], resolver=run.store.verify,
            producer_id=PRODUCER_ID, producer_version=PRODUCER_VERSION,
        )
        run.gate_reports.append(report)
        run.put_eval_document(
            f"claim-gate:{report['claim_gate_report_id']}", report, artifact_type="claim_gate_report",
            maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.SCHEMA_VALIDATED),
        )
    export = structured_evidence_export(ledger, run.gate_reports)
    claim_results = {
        claim["statement"]: report["gate_result"] for claim, report in zip(run.claim_records, run.gate_reports)
    }
    chapter = {
        "schema_version": "cipherlens.chapter4_evidence_view.v0.1",
        "evaluation_profile": dict(profile_link), "ledger": ledger_link,
        "sections": {
            "4.3": {"status": "UNLOCKED", "metric_refs": [metric_link(metrics[name]) for name in ("formal_test_population_count", "formal_test_passed_count", "formal_test_failed_count", "formal_test_skipped_count")], "claim_gate": run.gate_reports[0]["gate_result"]},
            "4.4": {"status": "UNLOCKED_SYNTHETIC", "metric_refs": [metric_link(metrics[name]) for name in ("required_slot_coverage", "merge_slot_coverage", "protected_region_preservation_rate")], "claim_gate": run.gate_reports[1]["gate_result"]},
            "4.5": {"status": "UNLOCKED_SYNTHETIC", "metric_refs": [metric_link(metrics[name]) for name in ("eligibility_evaluation_count", "ineligible_filter_count", "candidate_binding_count", "valid_binding_count")], "claim_gates": [run.gate_reports[2]["gate_result"], run.gate_reports[3]["gate_result"]]},
            "4.6": {"status": "UNLOCKED_SYNTHETIC", "metric_refs": [metric_link(metrics[name]) for name in ("satisfied_witness_count", "violated_witness_count", "unknown_witness_count")], "claim_gate": run.gate_reports[4]["gate_result"]},
            "4.7": {"status": "CONTROLLED_ABLATION_ONLY", "available": ["single-signal-vs-contract-driven"], "missing": ["real-world comparative ablation"]},
            "4.8": {"status": "NOT_UNLOCKED", "reason": "no CURRENT_V2 real third-party campaign", "claim_gate": run.gate_reports[5]["gate_result"]},
        },
    }
    ppt = {
        "schema_version": "cipherlens.ppt_evidence_view.v0.1",
        "available": ["engineering-validation", "rq1-synthetic", "rq2-synthetic", "rq3-synthetic"],
        "real_results_wall": {"status": "LOCKED", "reason": "evidence unavailable"},
        "claim_gate_results": claim_results,
    }
    export_link = run.put_json("exports/structured-evidence.json", export, artifact_type="structured_evidence_export")
    chapter_link = run.put_json("exports/chapter4-evidence-view.json", chapter, artifact_type="chapter4_evidence_view")
    ppt_link = run.put_json("exports/ppt-evidence-view.json", ppt, artifact_type="ppt_evidence_view")
    return {
        "ledger": ledger, "ledger_link": ledger_link, "export": export_link,
        "chapter4": chapter, "chapter4_link": chapter_link, "ppt": ppt, "ppt_link": ppt_link,
        "claim_results": claim_results,
    }


def run_evaluation(repo_root: Path, output_root: Path) -> dict[str, Any]:
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()
    run = EvaluationRun(repo_root, output_root, revision)
    profile = evaluation_profile(revision)
    profile_link = run.put_json(
        "profiles/evaluation-profile-v0.1.json", profile, artifact_type="evaluation_profile",
        schema_version=profile["schema_version"],
        maturity=(ValidationMaturity.DIGEST_VERIFIED, ValidationMaturity.UNIT_VALIDATED),
    )
    formal = run_formal_tests(run, profile)
    failed = sum(len(formal["identities"][key]) for key in ("failed", "errors"))
    if failed:
        defect = {
            "schema_version": "cipherlens.implementation_defect.v0.1", "git_revision": revision,
            "failed_test_identities": formal["identities"]["failed"],
            "error_test_identities": formal["identities"]["errors"],
        }
        run.put_json("exports/implementation-defect.json", defect, artifact_type="implementation_defect")
        raise RuntimeError("IMPLEMENTATION_DEFECT: formal regression contains failures/errors")
    with patch.object(socket.socket, "connect", _deny_network), patch.object(socket, "create_connection", _deny_network):
        rq1 = run_rq1(run)
        rq2 = run_rq2(run)
        rq3 = run_rq3(run)
    metrics = build_metrics(run, formal)
    outputs = build_claims_and_exports(run, metrics, rq1, rq2, rq3, profile_link)
    counts = {key: len(value) for key, value in formal["identities"].items()}
    summary = {
        "schema_version": "cipherlens.current_v2_evaluation_summary.v0.1",
        "evaluation_id": profile["evaluation_id"], "git_revision": revision,
        "artifact_root": "artifacts/evaluation_v2", "formal_regression": {
            "population": sum(counts.values()), "counts": counts,
            "suite_count": len(formal["suites"]), "test_run_records": len(run.test_run_records),
        },
        "experiments": {"rq1_units": len(rq1), "rq2_units": len(rq2), "rq3_units": len(rq3)},
        "metric_records": {
            name: {
                "numerator": record["numerator_value"], "denominator": record["denominator_value"],
                "recompute_status": record["recompute_status"],
            } for name, record in sorted(metrics.items())
        },
        "claim_gate_results": outputs["claim_results"],
        "policy_counters": run.policy_counters,
        "ledger": outputs["ledger_link"], "chapter4_view": outputs["chapter4_link"],
        "ppt_view": outputs["ppt_link"], "implementation_defects": [],
        "deviations": ["compiler profile is logical; no real compilation campaign was run"],
        "missing_evidence": ["CURRENT_V2 real third-party campaign", "real-world comparative ablation", "upstream confirmation"],
    }
    summary_link = run.put_json("exports/current-v2-summary.json", summary, artifact_type="evaluation_summary")
    index = {"summary": summary_link, "ledger": outputs["ledger_link"], "chapter4": outputs["chapter4_link"], "ppt": outputs["ppt_link"]}
    (output_root / "evaluation-index.json").write_bytes(_json_bytes(index))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", default="artifacts/evaluation_v2")
    args = parser.parse_args(argv)
    repo_root = Path.cwd().resolve()
    output_root = (repo_root / args.output_root).resolve()
    output_root.relative_to(repo_root)
    if output_root.exists() and any(output_root.iterdir()):
        raise SystemExit("evaluation output root must be absent or empty")
    summary = run_evaluation(repo_root, output_root)
    sys.stdout.write(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
