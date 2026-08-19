"""Create-only canonical preflight artifact root and deterministic B0 generator."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from target_knowledge.canonical import canonical_json_bytes
from .claim_gate_adapter import evaluate_preflight
from .population_manifest import make_population_manifest


class EvidenceRoot:
    def __init__(self, root: Path) -> None:
        self.root = root

    def write_json(self, relative_ref: str, value: Mapping[str, Any]) -> dict[str, str]:
        if relative_ref.startswith("/") or ".." in Path(relative_ref).parts:
            raise ValueError("artifact reference must be a safe relative path")
        payload = canonical_json_bytes(value)
        path = self.root / relative_ref
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != payload:
            raise FileExistsError(f"create-only artifact differs: {relative_ref}")
        if not path.exists():
            path.write_bytes(payload)
        return {"ref": relative_ref, "digest": hashlib.sha256(payload).hexdigest()}


def write_preflight_bundle(root: Path, profiles: list[Mapping[str, Any]], case_evidence: Mapping[str, Mapping[str, Mapping[str, str]]]) -> dict[str, Any]:
    evidence = EvidenceRoot(root)
    profile_links = [evidence.write_json(f"target_knowledge/{profile['profile_id']}.json", profile) for profile in profiles]
    manifest = make_population_manifest(case_evidence)
    manifest_link = evidence.write_json("population_manifests/CLV2-RQ4-PILOT-001.json", manifest)
    capture_example = {"schema_version": "cipherlens.oracle_event.v0.1", "example_only": True, "verdict_authority": "NONE", "status": "NOT_REACHED"}
    evidence.write_json("capture_bridge/oracle_event_v0_1.example.json", capture_example)
    preflight = evaluate_preflight(target_profiles=profiles, population_manifest=manifest)
    evidence.write_json("claim_gate_preflight/preflight.json", preflight)
    return {"profile_links": profile_links, "manifest_link": manifest_link, "preflight": preflight}


def _main() -> None:
    parser = argparse.ArgumentParser(description="Write B0 artifacts from supplied JSON profile files.")
    parser.add_argument("root", type=Path)
    parser.add_argument("--profiles", nargs="*", type=Path, default=[])
    args = parser.parse_args()
    profiles = [json.loads(path.read_text(encoding="utf-8")) for path in args.profiles]
    raise SystemExit("write_preflight_bundle requires explicit digest-addressed case evidence")


if __name__ == "__main__":
    _main()
