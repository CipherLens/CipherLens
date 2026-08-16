from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from caller_audit.external_caller_discovery import (
    ExternalCodeHit,
    MockExternalSearchProvider,
    build_search_queries,
    discover_external_callers,
    run_external_caller_discovery,
    validate_result,
)
from caller_audit.io_utils import load_yaml


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "caller_audit" / "schemas" / "external_caller_discovery_v1.yaml"


class ExternalCallerDiscoveryTest(unittest.TestCase):
    def _context_pack(self) -> dict[str, object]:
        return {
            "schema": "cipherlens_candidate_context_pack_v1",
            "candidate_id": "openssl-d2i-privatekey-full-consumption-gap",
            "library": "OpenSSL",
            "api_or_function": "d2i_PrivateKey",
            "semantic_type": "full_consumption_gap",
            "trigger_condition": "valid DER private key with trailing bytes",
        }

    def _write_context_pack(self, root: Path) -> Path:
        path = root / "candidate_context_pack.yaml"
        path.write_text(yaml.safe_dump(self._context_pack(), sort_keys=False), encoding="utf-8")
        return path

    def _mlspp_hit(self) -> ExternalCodeHit:
        return ExternalCodeHit(
            repository_name="cisco/mlspp",
            repository_url="https://github.com/cisco/mlspp",
            file_path="lib/hpke/src/rsa.cpp",
            file_url="https://github.com/cisco/mlspp/blob/main/lib/hpke/src/rsa.cpp",
            fragments=(
                "std::unique_ptr<Signature::PrivateKey>\n"
                "RSASignature::deserialize_private(const bytes& skm) const\n"
                "{\n"
                "  const auto* data_ptr = skm.data();\n"
                "  auto* pkey = d2i_PrivateKey(\n"
                "    EVP_PKEY_RSA, nullptr, &data_ptr, static_cast<int>(skm.size()));\n"
                "  return std::make_unique<RSASignature::PrivateKey>(pkey);\n"
                "}",
            ),
        )

    def test_query_generation_uses_api_and_semantic_terms(self):
        queries = build_search_queries(self._context_pack())

        self.assertIn('"d2i_PrivateKey("', queries)
        self.assertIn("d2i_PrivateKey", queries)
        self.assertIn('"EVP_PKEY *d2i_PrivateKey"', queries)
        self.assertIn("d2i_PrivateKey DER", queries)
        self.assertIn("d2i_PrivateKey ASN.1", queries)
        self.assertIn('d2i_PrivateKey "key parsing"', queries)
        self.assertIn("d2i_PrivateKey PKCS8", queries)

    def test_mock_github_response_discovers_mlspp_private_key_caller(self):
        provider = MockExternalSearchProvider(
            {
                '"d2i_PrivateKey("': [self._mlspp_hit()],
                "d2i_PrivateKey": [self._mlspp_hit()],
            }
        )
        result = discover_external_callers(self._context_pack(), provider)

        self.assertEqual(result["schema"], "cipherlens_external_caller_discovery_v1")
        self.assertEqual(len(result["repositories"]), 1)
        repo = result["repositories"][0]
        self.assertEqual(repo["name"], "cisco/mlspp")
        self.assertEqual(repo["file"], "lib/hpke/src/rsa.cpp")
        self.assertEqual(repo["symbol"], "hpke::RSASignature::deserialize_private")
        self.assertEqual(repo["relevance"], "high")
        self.assertTrue(any("d2i_PrivateKey" in item for item in repo["evidence"]))
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(result["claim_policy"]["security_impact"], "not_assessed")

    def test_ranking_prefers_security_source_over_tests(self):
        test_hit = ExternalCodeHit(
            repository_name="openssl/openssl",
            repository_url="https://github.com/openssl/openssl",
            file_path="test/x509_test.c",
            file_url="https://github.com/openssl/openssl/blob/master/test/x509_test.c",
            fragments=("privkey = d2i_PrivateKey(EVP_PKEY_EC, NULL, &p, sizeof(privkeydata));",),
        )
        provider = MockExternalSearchProvider({'"d2i_PrivateKey("': [test_hit, self._mlspp_hit()]})
        result = discover_external_callers(self._context_pack(), provider)

        self.assertEqual(result["repositories"][0]["name"], "cisco/mlspp")
        self.assertEqual(result["repositories"][0]["relevance"], "high")
        self.assertEqual(result["repositories"][1]["name"], "openssl/openssl")
        self.assertEqual(result["repositories"][1]["relevance"], "medium")

    def test_schema_validation_accepts_written_result(self):
        provider = MockExternalSearchProvider({'"d2i_PrivateKey("': [self._mlspp_hit()]})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context_path = self._write_context_pack(root)
            output_path = root / "external_caller_discovery.yaml"
            result = run_external_caller_discovery(
                context_path,
                output_path,
                provider,
                schema_path=SCHEMA_PATH,
            )
            loaded = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        self.assertEqual(result, loaded)
        validate_result(loaded, self._context_pack(), load_yaml(SCHEMA_PATH))

    def test_no_result_case_reports_unknown(self):
        result = discover_external_callers(self._context_pack(), MockExternalSearchProvider({}))

        self.assertEqual(result["repositories"], [])
        self.assertIn("No external repository candidate", result["unknowns"][0])
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")


if __name__ == "__main__":
    unittest.main()
