from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from target_knowledge.canonical import semantic_digest, semantic_safety_errors
from target_knowledge.openssl_profile import materialize_openssl_355_profile
from target_knowledge.source_index import tree_digest
from target_knowledge.verifier import EvidenceStatus, verify_evidence_record
from target_knowledge.wolfssl_profile import materialize_wolfssl_591_blocked_profile


class TargetKnowledgeTests(unittest.TestCase):
    def _openssl_tree(self) -> tempfile.TemporaryDirectory[str]:
        directory = tempfile.TemporaryDirectory()
        root = Path(directory.name)
        (root / "include" / "openssl").mkdir(parents=True)
        (root / "include" / "openssl" / "rsa.h").write_text("RSA *d2i_RSAPrivateKey(void);\n")
        (root / "include" / "openssl" / "evp.h").write_text("int EVP_DecryptFinal_ex(void);\n")
        (root / "configdata.pm").write_text("config=v1\n")
        (root / "libcrypto.a").write_bytes(b"fake-static-library")
        return directory

    def test_tree_digest_is_deterministic(self):
        with self._openssl_tree() as path:
            self.assertEqual(tree_digest(Path(path)), tree_digest(Path(path)))

    def test_openssl_profile_has_release_identity_and_verified_header_evidence(self):
        with self._openssl_tree() as path:
            root = Path(path)
            profile = materialize_openssl_355_profile(root)
            expected_library_digest = hashlib.sha256((root / "libcrypto.a").read_bytes()).hexdigest()
        self.assertEqual(profile["git_or_release_identity"]["kind"], "release")
        self.assertTrue(any(item["verification_status"] == "VERIFIED" for item in profile["evidence_records"]))
        self.assertTrue(all(len(item["digest"]) == 64 for item in profile["library_artifacts"]))
        self.assertEqual(profile["library_artifacts"][0]["digest"], expected_library_digest)
        self.assertEqual(profile["validation_status"], "PREPARED")

    def test_config_digest_changes_profile_identity(self):
        with self._openssl_tree() as path:
            root = Path(path)
            one = materialize_openssl_355_profile(root)
            (root / "configdata.pm").write_text("config=v2\n")
            two = materialize_openssl_355_profile(root)
        self.assertNotEqual(one["profile_id"], two["profile_id"])

    def test_draft_api_cards_cannot_self_verify(self):
        self.assertEqual(verify_evidence_record({"evidence_type": "API_CARD", "lifecycle": "draft"}), EvidenceStatus.CANDIDATE)
        self.assertEqual(verify_evidence_record({"evidence_type": "RAG_RESULT", "score": 1.0}), EvidenceStatus.CANDIDATE)

    def test_wolfssl_is_explicitly_blocked(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            (root / "x.c").write_text("int x;\n")
            profile = materialize_wolfssl_591_blocked_profile(root, "abc")
        self.assertEqual(profile["validation_status"], "NOT_READY")
        self.assertTrue(all(item["verification_status"] == "CANDIDATE" for item in profile["evidence_records"]))

    def test_telemetry_is_not_semantic_identity(self):
        one = {"x": "safe", "telemetry": {"local_path": "/tmp/one"}}
        two = {"x": "safe", "telemetry": {"local_path": "/tmp/two"}}
        self.assertEqual(semantic_digest(one), semantic_digest(two))

    def test_absolute_semantic_path_is_rejected(self):
        self.assertTrue(semantic_safety_errors({"path": "/private/local"}))

    def test_telemetry_allows_local_path_but_not_secret(self):
        self.assertFalse(semantic_safety_errors({"telemetry": {"local_path": "/tmp/local"}}))
        self.assertTrue(semantic_safety_errors({"telemetry": {"token": "never"}}))

    def test_incomplete_source_record_stays_candidate(self):
        self.assertEqual(verify_evidence_record({"evidence_type": "HEADER_SIGNATURE", "symbol": "x"}), EvidenceStatus.CANDIDATE)


if __name__ == "__main__":
    unittest.main()
