"""Fact-only producer; it has no evaluator or Verdict dependency."""
from .canonical import FORBIDDEN,digest
from .model import ROLES,SCHEMA,STATUSES
_REQUIRED={"execution_attempt_ref","contract_observable_ref","observation_binding_ref","merge_capture_ref","semantic_role","acquisition_kind","phase","subject_ref","operation_ref","correlation_group_ref","status","value_type","value","evidence_refs","producer"}
def emit_runtime_event_v0_1(**fields):
 if set(fields)&FORBIDDEN: raise ValueError("forbidden RuntimeEvent field")
 missing=_REQUIRED-set(fields)
 if missing: raise ValueError("missing RuntimeEvent fields: "+",".join(sorted(missing)))
 if fields["semantic_role"] not in ROLES or fields["status"] not in STATUSES: raise ValueError("invalid RuntimeEvent vocabulary")
 producer=fields["producer"]
 if not isinstance(producer,dict) or set(producer)!={"emitter_name","emitter_version"}: raise ValueError("invalid producer")
 event={"schema_version":SCHEMA,**fields}
 event["runtime_event_id"]="runtime-event:"+digest(event)
 event["event_digest"]=digest(event)
 return event
