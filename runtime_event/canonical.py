import hashlib, json
FORBIDDEN={"verdict","satisfied","violated","vulnerability","cve","security_finding","safe","llm_confidence","timestamp","pid","hostname","telemetry"}
def canonical_bytes(value): return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode()
def digest(value): return hashlib.sha256(canonical_bytes(value)).hexdigest()
