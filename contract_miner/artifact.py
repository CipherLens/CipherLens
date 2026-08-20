"""Create-only canonical Contract artifact records for execution lineage."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping

import yaml

from .schema import canonical_vc_bytes, contract_digest, validate_vc_or_raise


def materialize_contract_artifact(contract_path: str | Path, validation_path: str | Path, *, repo_root: str | Path) -> tuple[dict[str, Any], bytes]:
    root=Path(repo_root).resolve(); source=Path(contract_path); validation_source=Path(validation_path)
    contract=yaml.safe_load(source.read_text(encoding="utf-8")); validation=yaml.safe_load(validation_source.read_text(encoding="utf-8"))
    validate_vc_or_raise(contract, repo_root=root)
    payload=canonical_vc_bytes(contract); digest=hashlib.sha256(payload).hexdigest()
    status="VALID" if validation.get("status")=="PASS" and validation.get("provenance",{}).get("contract_sha256")==digest else "INVALID"
    record={"schema_version":"cipherlens.contract_artifact_record.v0.1","contract_artifact_id":"contract-artifact:"+digest,"contract_ref":"contract:"+contract["contract_id"],"contract_schema_version":contract["schema_version"],"contract_digest":contract_digest(contract),"canonical_bytes_digest":digest,"artifact_ref":"artifacts/pipeline_v2/contracts/"+contract["contract_id"].lower()+".vc.yaml","source_validation_ref":str(validation_source.relative_to(root)),"source_validation_digest":hashlib.sha256(validation_source.read_bytes()).hexdigest(),"producer":"contract_miner","producer_version":"v0.3","git_revision":contract["source"]["fixed_revision"],"creation_scope":"SINGLE_UNIT_DRY_RUN_PREP","validation_status":status}
    return record,payload
