from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from caller_audit.source_caller_discovery import run_source_caller_discovery


class SourceCallerDiscoveryTest(unittest.TestCase):
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

    def _write_libdkimpp(self, workspace: Path) -> Path:
        project = workspace / "libdkimpp"
        source = project / "src" / "PublicKey.cpp"
        source.parent.mkdir(parents=True)
        source.write_text(
            """#include <openssl/x509.h>

namespace DKIM {

class PublicKey
{
public:
  static PublicKey Parse(const std::string& record);
};

PublicKey
PublicKey::Parse(const std::string& record)
{
  auto decoded_spki = Base64_Decode(record);
  const unsigned char* tmp2 = decoded_spki.data();
  EVP_PKEY* publicKey = d2i_PUBKEY(nullptr, &tmp2, decoded_spki.size());
  RSA_verify(NID_sha256, nullptr, 0, nullptr, 0, EVP_PKEY_get0_RSA(publicKey));
  return PublicKey();
}

}
""",
            encoding="utf-8",
        )
        return project

    def _write_mlspp(self, workspace: Path) -> Path:
        project = workspace / "mlspp"
        source = project / "lib" / "hpke" / "src" / "certificate.cpp"
        source.parent.mkdir(parents=True)
        source.write_text(
            """#include <openssl/x509.h>

namespace MLS_NAMESPACE::hpke {

struct Certificate
{
  struct ParsedCertificate
  {
    static std::unique_ptr<ParsedCertificate> parse(const bytes& der)
    {
      const auto* buf = der.data();
      auto cert = make_typed_unique(d2i_X509(nullptr, &buf, static_cast<int>(der.size())));
      X509_verify(cert.get(), nullptr);
      return std::make_unique<ParsedCertificate>();
    }
  };
};

}
""",
            encoding="utf-8",
        )
        return project

    def test_d2i_pubkey_finds_libdkimpp_public_key_parse_from_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "projects"
            workspace.mkdir()
            self._write_libdkimpp(workspace)
            context = self._write_context_pack(
                root,
                candidate_id="openssl-d2i-pubkey-full-consumption-gap",
                api="d2i_PUBKEY",
            )
            result = run_source_caller_discovery(
                context,
                workspace,
                root / "source_caller_discovery.yaml",
            )

        matches = [
            caller
            for caller in result["discovered_callers"]
            if caller["repository"]["name"] == "libdkimpp"
            and caller["symbol"] == "DKIM::PublicKey::Parse"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["relevance"], "high")
        self.assertEqual(matches[0]["file"], "src/PublicKey.cpp")
        self.assertTrue(any("d2i_PUBKEY" in item for item in matches[0]["evidence"]))
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(result["claim_policy"]["security_impact"], "not_assessed")

    def test_d2i_x509_finds_mlspp_parsed_certificate_parse_from_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "projects"
            workspace.mkdir()
            self._write_mlspp(workspace)
            context = self._write_context_pack(
                root,
                candidate_id="openssl-x509-full-consumption-gap",
                api="d2i_X509",
            )
            result = run_source_caller_discovery(
                context,
                workspace,
                root / "source_caller_discovery.yaml",
            )

        matches = [
            caller
            for caller in result["discovered_callers"]
            if caller["repository"]["name"] == "mlspp"
            and caller["symbol"] == "Certificate::ParsedCertificate::parse"
        ]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["relevance"], "high")
        self.assertEqual(matches[0]["file"], "lib/hpke/src/certificate.cpp")
        self.assertTrue(any("d2i_X509" in item for item in matches[0]["evidence"]))
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")
        self.assertEqual(result["claim_policy"]["security_impact"], "not_assessed")

    def test_unknown_when_no_source_caller_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "projects"
            workspace.mkdir()
            project = workspace / "boring-project"
            project.mkdir()
            (project / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
            context = self._write_context_pack(
                root,
                candidate_id="openssl-d2i-pubkey-full-consumption-gap",
                api="d2i_PUBKEY",
            )
            result = run_source_caller_discovery(
                context,
                workspace,
                root / "source_caller_discovery.yaml",
            )

        self.assertEqual(result["discovered_callers"], [])
        self.assertIn("No source-level caller", result["unknowns"][0])
        self.assertEqual(result["claim_policy"]["vulnerability"], "not_assessed")


if __name__ == "__main__":
    unittest.main()
