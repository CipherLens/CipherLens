from .canonical import digest
def attach_runtime_event(event,execution_witness_ref,attached_at_revision):
 if not execution_witness_ref or execution_witness_ref.startswith("pending"): raise ValueError("future witness forbidden")
 return {"schema_version":"cipherlens.runtime_event_witness_attachment.v0.1","runtime_event_ref":event["runtime_event_id"],"runtime_event_digest":event["event_digest"],"execution_witness_ref":execution_witness_ref,"attached_at_revision":attached_at_revision,"attachment_id":"runtime-event-attachment:"+digest({"event":event["runtime_event_id"],"witness":execution_witness_ref,"revision":attached_at_revision})}
