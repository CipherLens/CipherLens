"""C1-fix11 Contract artifact lineage repair; no build or execution."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
from typing import Any
from contract_miner.artifact import materialize_contract_artifact
from target_knowledge.canonical import canonical_json_bytes, identified

OUTPUT=Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix11-v0.1")
CONTRACTS=Path("artifacts/pipeline_v2/contracts")
FIXTURE=Path("tests/contract_miner/fixtures/golden/mbedtls_poc_0020/expected.vc.yaml")
VALIDATION=Path("tests/contract_miner/fixtures/golden/mbedtls_poc_0020/expected.validation.yaml")
PARENTS={"c1_retry_v0_4":Path("artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.4/artifact_index.json"),"c1_fix10":Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix10-v0.1/artifact_index.json"),"c1_fix9":Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix9-v0.1/artifact_index.json")}
def edge(root:Path,ref:Path|str):
 p=root/ref; return {"ref":str(ref),"digest":hashlib.sha256(p.read_bytes()).hexdigest()}
def make(repo_root:str|Path):
 root=Path(repo_root).resolve(); record,payload=materialize_contract_artifact(root/FIXTURE,root/VALIDATION,repo_root=root); artifact_ref=CONTRACTS/"rsa_der_full_consumption.vc.yaml"; artifact_edge={"ref":str(artifact_ref),"digest":hashlib.sha256(payload).hexdigest()}; parents={k:edge(root,v) for k,v in PARENTS.items()}; common={"unit_id":"unit:track-a:0020:fixed","scope":"SINGLE_UNIT_DRY_RUN_PREP","campaign_scope":"NOT_FULL_CAMPAIGN","report_real_number_allowed":False,"parent_artifacts":parents}
 bytes_doc=identified({"schema_version":"cipherlens.contract_canonical_bytes.v0.1",**common,"contract_ref":record["contract_ref"],"canonical_bytes_digest":artifact_edge["digest"],"encoding":"UTF-8","serialization":"canonical_vc_bytes_sorted_keys","canonical_utf8":payload.decode("utf-8")},"c1-fix11-contract-bytes","bytes_id")
 record={**record,"artifact_ref":artifact_edge["ref"],"artifact_digest":artifact_edge["digest"]}
 lineage=identified({"schema_version":"cipherlens.contract_lineage_record.v0.1",**common,"status":record["validation_status"],"contract_artifact":record,"canonical_bytes":{"ref":str(OUTPUT/"contract_bytes.json"),"digest":hashlib.sha256(canonical_json_bytes(bytes_doc)).hexdigest()},"source_contract_fixture":edge(root,FIXTURE),"authority":"VALIDATED_CONTRACT_INSTANCE_CANONICALIZATION_ONLY"},"c1-fix11-contract-lineage","lineage_id")
 alignment=identified({"schema_version":"cipherlens.execution_handoff_contract_alignment.v0.1",**common,"status":"READY" if record["validation_status"]=="VALID" else "BLOCKED","contract_ref":record["contract_ref"],"contract_digest":record["contract_digest"],"contract_artifact_ref":artifact_edge["ref"],"contract_artifact_digest":artifact_edge["digest"],"lineage_record_ref":str(OUTPUT/"contract_lineage_record.json"),"lineage_record_digest":hashlib.sha256(canonical_json_bytes(lineage)).hexdigest(),"frozen_execution_handoff_schema_modified":False},"c1-fix11-handoff-contract-alignment","alignment_id")
 gate=identified({"schema_version":"cipherlens.c1_fix11_pre_run_gate.v0.1",**common,"status":"C1_PRE_RUN_GATE_REPAIRED_READY_TO_RETRY" if alignment["status"]=="READY" else "C1_PRE_RUN_GATE_STILL_BLOCKED","cleared_blocking_reasons":["CONTRACT_ARTIFACT_LINEAGE_MISSING"] if alignment["status"]=="READY" else [],"allowed_next_stage":"C1_RETRY_ONLY" if alignment["status"]=="READY" else "C1_FIX_ONLY","build_attempted":False,"run_attempted":False,"runtime_event_generated":False,"witness_generated":False,"trace_generated":False,"relation_evaluation_generated":False,"execution_verdict_generated":False},"c1-fix11-pre-run-gate","decision_id")
 docs={"contract_artifact.json":record,"contract_bytes.json":bytes_doc,"contract_lineage_record.json":lineage,"execution_handoff_contract_alignment.json":alignment,"c1_pre_run_gate_decision.json":gate}; index=identified({"schema_version":"cipherlens.c1_fix11_artifact_index.v0.1",**common,"status":gate["status"],"artifacts":[{"artifact_type":n[:-5],"ref":str(OUTPUT/n),"digest":hashlib.sha256(canonical_json_bytes(d)).hexdigest()} for n,d in sorted(docs.items())]+[{"artifact_type":"canonical_contract","ref":str(artifact_ref),"digest":artifact_edge["digest"]}],"create_only":True},"c1-fix11-index","index_id"); docs["artifact_index.json"]=index; return artifact_ref,payload,docs
def write(repo_root:str|Path):
 root=Path(repo_root).resolve(); out=root/OUTPUT; contracts=root/CONTRACTS
 if out.exists() or (contracts/"rsa_der_full_consumption.vc.yaml").exists(): raise FileExistsError("C1-fix11 artifacts are create-only")
 ref,payload,docs=make(root); contracts.mkdir(parents=True); (root/ref).write_bytes(payload); out.mkdir(parents=True)
 for name,doc in docs.items(): (out/name).write_bytes(canonical_json_bytes(doc))
 return {"contract":root/ref,**{name:out/name for name in docs}}
