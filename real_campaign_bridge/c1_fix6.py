"""C1-fix6 deterministic interface overlay, without source execution."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping
from target_knowledge.canonical import canonical_json_bytes, identified
from .c1_gate import APPROVED_UNIT_ID, CAMPAIGN_SCOPE

SCOPE="SINGLE_UNIT_DRY_RUN_PREP"
OUT=Path("artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix6-v0.1")
PARENT5="artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix5-v0.1/artifact_index.json"
PARENT4="artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix4-v0.1/artifact_index.json"
PARENT_RETRY="artifacts/pipeline_v2/single_unit_dry_run/c1-retry-v0.1/artifact_index.json"

def _edge(root:Path,ref:str)->dict[str,str]: return {"ref":ref,"digest":hashlib.sha256((root/ref).read_bytes()).hexdigest()}
def overlay(root: str|Path)->dict[str,Any]:
 root=Path(root).resolve()
 merge=json.loads((root/"artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage/merge.json").read_text())
 holes=[
  ("hole:der-kind","DER_KIND","enum/string","source-side private-key operation binding"),
  ("hole:parse-api-kind","PARSE_API_KIND","enum/string","source-side RSA private parser operation binding"),
  ("hole:trailing-garbage-bytes","TRAILING_GARBAGE_BYTES","bytes/hex","declared trailing-data intervention metadata"),
  ("hole:trailing-garbage-len","TRAILING_GARBAGE_LEN","integer","byte length derived from hole:trailing-garbage-bytes"),
  ("hole:expect-ret","EXPECT_RET","integer/enum","fixed-side expected rejection relation guard"),]
 return identified({"schema_version":"cipherlens.c1_template_interface_overlay.v0.1","unit_id":APPROVED_UNIT_ID,"scope":SCOPE,"campaign_scope":CAMPAIGN_SCOPE,"execution_status":"NOT_EXECUTED","report_real_number_allowed":False,"parent_artifacts":{"c1_retry":_edge(root,PARENT_RETRY),"c1_fix5":_edge(root,PARENT5),"c1_fix4":_edge(root,PARENT4)},"parent_template_interface":{"ref":merge["trigger_template_interface_ref"],"digest":merge["trigger_template_interface_digest"]},"deterministic_value_holes":[{"hole_ref":h,"value_key":k,"expected_value_type":t,"resolver_source":s,"execution_blocking":True,"protected_region_mutation_forbidden":True} for h,k,t,s in holes],"capture_hole":{"hole_ref":"hole:oracle-event-capture","kind":"OBSERVATION_CAPTURE_GLUE","allowed_source_map_region":"region:c1-overlay:oracle-event-capture","protected_region_mutation_forbidden":True,"required_roles":["operation_outcome","consumed_length","input_length"],"correlation_group_ref":"CORRELATION_PRIMARY"},"authority":"C1_SPECIFIC_OVERLAY_DECLARATION_ONLY"},"c1-fix6-overlay","overlay_id")
def resolution(root:str|Path, ov:Mapping[str,Any])->dict[str,Any]:
 root=Path(root).resolve(); values={"hole:der-kind":("private","enum/string"),"hole:parse-api-kind":("rsa_private","enum/string"),"hole:trailing-garbage-bytes":("020100","bytes/hex"),"hole:trailing-garbage-len":(3,"integer"),"hole:expect-ret":("MBEDTLS_ERR_RSA_BAD_INPUT_DATA","integer/enum")}
 items=[]
 for h,v in values.items():
  item={"hole_ref":h,"value":v[0],"value_type":v[1],"source_refs":[_edge(root,"artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage/merge.json")],"resolver_id":"cipherlens.c1_fix6.deterministic_overlay_resolver","resolver_version":"v0.1","reason_code":"DECLARED_SOURCE_SIDE_DETERMINISTIC_VALUE","derivation_rule":"declared overlay resolver"}; item["digest"]=hashlib.sha256(canonical_json_bytes(item)).hexdigest(); items.append(item)
 return identified({"schema_version":"cipherlens.c1_deterministic_value_resolution.v0.1","unit_id":APPROVED_UNIT_ID,"scope":SCOPE,"campaign_scope":CAMPAIGN_SCOPE,"execution_status":"NOT_EXECUTED","report_real_number_allowed":False,"overlay":{"ref":"c1-fix6-overlay","digest":hashlib.sha256(canonical_json_bytes(ov)).hexdigest()},"status":"COMPLETE","resolved_values":items,"unresolved":[],"authority":"NO_LLM_NO_RAG_DECLARED_HOLES_ONLY"},"c1-fix6-resolution","resolution_id")
def write_blocked(root:str|Path,ov:Mapping[str,Any],res:Mapping[str,Any])->dict[str,Path]:
 root=Path(root).resolve(); out=root/OUT
 if out.exists(): raise FileExistsError("create-only c1-fix6 root exists")
 out.mkdir(parents=True); common={"unit_id":APPROVED_UNIT_ID,"scope":SCOPE,"campaign_scope":CAMPAIGN_SCOPE,"execution_status":"NOT_EXECUTED","report_real_number_allowed":False}
 def edge(n,d): return {"ref":str(OUT/n),"digest":hashlib.sha256(canonical_json_bytes(d)).hexdigest()}
 oe,re=edge("template_interface_overlay.json",ov),edge("deterministic_value_resolution.json",res)
 cap=identified({"schema_version":"cipherlens.c1_capture_hook_spec.v0.2",**common,"overlay":oe,"resolution":re,"status":"PROTOCOL_MATERIALIZATION_BLOCKED","declared_source_map_region":"region:c1-overlay:oracle-event-capture","required_marker":"ORACLE_EVENT_V0_1","required_roles":["operation_outcome","consumed_length","input_length"],"reason_code":"FROZEN_ORACLE_EVENT_IDENTITY_PROTOCOL_REQUIRES_RUNTIME_DIGEST_AND_ID","hook_generated":False,"verdict_authority":"NONE"},"c1-fix6-capture","spec_id")
 reason="CAPTURE_HOOK_PROTOCOL_UNMATERIALIZABLE"
 src=identified({"schema_version":"cipherlens.c1_bound_source_materialization.v0.2",**common,"status":"NOT_GENERATED","reason_code":reason,"protected_region_mutated":False},"c1-fix6-source","materialization_id")
 sm=identified({"schema_version":"cipherlens.c1_source_map_update.v0.2",**common,"status":"NOT_GENERATED","reason_code":reason,"protected_region_mutated":False},"c1-fix6-map","update_id")
 hand=identified({"schema_version":"cipherlens.c1_execution_handoff_readiness.v0.2",**common,"status":"NOT_READY","reason_codes":[reason],"build_spec_materializable":False,"run_spec_materializable":False},"c1-fix6-handoff","readiness_id")
 gate=identified({"schema_version":"cipherlens.c1_fix6_pre_run_gate.v0.1",**common,"status":"C1_PRE_RUN_GATE_STILL_BLOCKED","blocking_reasons":[reason],"build_run_authorized":False,"witness_generated":False,"structured_trace_generated":False,"execution_verdict_generated":False,"violation_evidence_package_generated":False},"c1-fix6-gate","decision_id")
 docs={"template_interface_overlay.json":ov,"deterministic_value_resolution.json":res,"capture_hook_spec.json":cap,"bound_source_materialization.json":src,"source_map_update.json":sm,"execution_handoff_readiness.json":hand,"c1_pre_run_gate_decision.json":gate}
 idx=identified({"schema_version":"cipherlens.c1_fix6_index.v0.1",**common,"status":"C1_PRE_RUN_GATE_STILL_BLOCKED","parent_artifacts":ov["parent_artifacts"],"artifacts":[{"artifact_type":n[:-5],**edge(n,d)} for n,d in sorted(docs.items())]},"c1-fix6-index","index_id"); docs["artifact_index.json"]=idx
 for n,d in docs.items():(out/n).write_bytes(canonical_json_bytes(d))
 return {n:out/n for n in docs}
