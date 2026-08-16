from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

from caller_audit.external_caller_discovery import ExternalCodeHit, MockExternalSearchProvider
from caller_audit.caller_discovery_runner import run_caller_discovery
from utils.agent_provider import AgentProvider


ROOT = Path(__file__).resolve().parents[1]


class MockDiscoveryProvider(AgentProvider):
    @property
    def name(self) -> str:
        return "mock-discovery"

    def analyze(self, context_pack: dict[str, Any]) -> dict[str, Any]:
        local = context_pack["local_evidence"]
        result = dict(local)
        result["candidate_id"] = context_pack["context_pack"]["candidate_id"]
        return result


class RecordingMockGitHubSearchProvider(MockExternalSearchProvider):
    def __init__(self, results_by_query: dict[str, list[ExternalCodeHit]]) -> None:
        super().__init__(results_by_query)
        self.queries: list[str] = []

    def search(self, query: str, *, per_page: int) -> list[ExternalCodeHit]:
        self.queries.append(query)
        return super().search(query, per_page=per_page)


class CallerDiscoveryRunnerTest(unittest.TestCase):
    def _write_context_pack(self, root: Path, *, candidate_id: str, api: str) -> Path:
        path = root / "candidate_context_pack.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema": "cipherlens_candidate_context_pack_v1",
                    "candidate_id": candidate_id,
                    "library": "OpenSSL",
                    "api_or_function": api,
                    "semantic_type": "full_consumption_gap",
                    "trigger_condition": "DER valid prefix plus trailing bytes",
                    "evidence": [
                        {
                            "source": "unit-test",
                            "observation": "API candidate only; caller not supplied.",
                        }
                    ],
                    "claim_policy": {
                        "vulnerability": "not_assessed",
                        "security_impact": "not_assessed",
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return path

    def _write_mac_candidate(self, root: Path) -> Path:
        path = root / "openssl_cmac_lifecycle_candidate.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema": "cipherlens_caller_discovery_candidate_v1",
                    "candidate": {
                        "library": "OpenSSL",
                        "api": ["EVP_MAC_update", "EVP_MAC_final"],
                        "family": "mac_lifecycle_semantic_divergence",
                        "behavior": [
                            "update_after_final_allowed",
                            "repeated_final_allowed",
                        ],
                        "evidence": [
                            "artifacts/triage/mac_cmac_double_final_minimal/results/cmac_double_final_summary.json"
                        ],
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return path

    def _run(self, context_path: Path, output_path: Path) -> dict[str, Any]:
        return run_caller_discovery(
            context_path,
            output_path,
            evidence_roots=[
                ROOT / "caller_audit",
                ROOT / "artifacts" / "caller_audit",
                ROOT / "knowledge_raw",
                ROOT / "knowledge_base" / "api_cards",
            ],
            timestamp_factory=lambda: "2026-08-13T00:00:00+00:00",
        )

    def test_d2i_pubkey_discovers_libdkimpp_public_key_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(
                root,
                candidate_id="openssl-d2i-pubkey-full-consumption-gap",
                api="d2i_PUBKEY",
            )
            artifact = self._run(context_path, root / "caller_discovery.yaml")

        result = artifact["result"]
        self.assertEqual(result["candidate_id"], "openssl-d2i-pubkey-full-consumption-gap")
        matches = [
            caller
            for caller in result["discovered_callers"]
            if caller["repository"]["name"] == "libdkimpp"
            and caller["symbol"] == "DKIM::PublicKey::Parse"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["relevance"], "high")
        self.assertTrue(any("d2i_PUBKEY" in item for item in matches[0]["evidence"]))
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(result["claim_policy"]["security_impact"], "not_assessed")

    def test_d2i_x509_discovers_mlspp_parsed_certificate_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(
                root,
                candidate_id="openssl-x509-full-consumption-gap",
                api="d2i_X509",
            )
            artifact = self._run(context_path, root / "caller_discovery.yaml")

        result = artifact["result"]
        matches = [
            caller
            for caller in result["discovered_callers"]
            if caller["repository"]["name"] == "mlspp"
            and caller["symbol"] == "Certificate::ParsedCertificate::parse"
        ]
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(matches[0]["relevance"], "high")
        self.assertTrue(any("lib/hpke/src/certificate.cpp:96" in item for item in matches[0]["evidence"]))
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(result["claim_policy"]["security_impact"], "not_assessed")

    def test_artifact_schema_and_provider_metadata_are_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(
                root,
                candidate_id="openssl-d2i-pubkey-full-consumption-gap",
                api="d2i_PUBKEY",
            )
            output_path = root / "caller_discovery.yaml"
            artifact = self._run(context_path, output_path)
            loaded = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(artifact, loaded)
        self.assertEqual(loaded["schema"], "cipherlens_caller_discovery_v1")
        self.assertEqual(loaded["provider"]["name"], "local-evidence-caller-discovery")
        self.assertFalse(loaded["provider"]["network"])
        self.assertEqual(len(loaded["source_context_pack"]["sha256"]), 64)
        self.assertEqual(loaded["claim_policy"]["vulnerability"], "not_assessed")
        self.assertTrue(loaded["claim_policy"]["caller_discovery_only"])

    def test_injected_provider_can_return_local_evidence_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(
                root,
                candidate_id="openssl-d2i-pubkey-full-consumption-gap",
                api="d2i_PUBKEY",
            )
            artifact = run_caller_discovery(
                context_path,
                root / "caller_discovery.yaml",
                MockDiscoveryProvider(),
                evidence_roots=[ROOT / "caller_audit", ROOT / "artifacts" / "caller_audit"],
                timestamp_factory=lambda: "2026-08-13T00:00:00+00:00",
            )

        self.assertEqual(artifact["provider"]["name"], "mock-discovery")
        self.assertTrue(artifact["result"]["discovered_callers"])

    def test_missing_required_candidate_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_path = self._write_mac_candidate(root)
            data = yaml.safe_load(candidate_path.read_text(encoding="utf-8"))
            data["candidate"].pop("family")
            candidate_path.write_text(yaml.safe_dump(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "family"):
                run_caller_discovery(
                    candidate_path,
                    root / "caller_discovery.yaml",
                    evidence_roots=[],
                    workspace_roots=[],
                )

    def test_mock_github_search_discovers_lua_openssl_without_input_hint(self):
        hit = ExternalCodeHit(
            repository_name="zhaozg/lua-openssl",
            repository_url="https://github.com/zhaozg/lua-openssl",
            file_path="src/mac.c",
            file_url="https://github.com/zhaozg/lua-openssl/blob/master/src/mac.c",
            fragments=(
                "static int openssl_mac_update(lua_State *L) {\n"
                "  return EVP_MAC_update(ctx, data, len);\n"
                "}\n"
                "static int openssl_mac_final(lua_State *L) {\n"
                "  return EVP_MAC_final(ctx, out, &outl, outsize);\n"
                "}",
            ),
        )
        provider = RecordingMockGitHubSearchProvider(
            {'"EVP_MAC_update" "EVP_MAC_final" CMAC': [hit]}
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate_path = self._write_mac_candidate(root)
            input_text = candidate_path.read_text(encoding="utf-8")
            self.assertNotIn("lua-openssl", input_text)
            artifact = run_caller_discovery(
                candidate_path,
                root / "caller_discovery.yaml",
                evidence_roots=[],
                workspace_roots=[],
                external_provider=provider,
                timestamp_factory=lambda: "2026-08-13T00:00:00+00:00",
            )

        self.assertTrue(provider.queries)
        self.assertFalse(any("lua-openssl" in query for query in provider.queries))
        self.assertIn('"EVP_MAC_update" "EVP_MAC_final" CMAC', provider.queries)
        self.assertEqual(artifact["candidate"]["library"], "OpenSSL")
        self.assertEqual(
            artifact["candidate"]["api"],
            ["EVP_MAC_update", "EVP_MAC_final"],
        )
        self.assertEqual(artifact["claim_policy"]["vulnerability"], "not_assessed")
        repos = [repo["name"] for repo in artifact["repositories"]]
        self.assertIn("zhaozg/lua-openssl", repos)
        sites = [
            site for site in artifact["call_sites"]
            if site["repository"] == "zhaozg/lua-openssl"
        ]
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["file"], "src/mac.c")
        self.assertIn("EVP_MAC_update", sites[0]["matched_api"])
        self.assertTrue(
            any(
                item["search_query"] == '"EVP_MAC_update" "EVP_MAC_final" CMAC'
                for item in artifact["evidence"]
            )
        )


if __name__ == "__main__":
    unittest.main()
