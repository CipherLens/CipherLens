from __future__ import annotations

from copy import deepcopy
import unittest

from tests.candidate_binding.common import CASE_TEMPLATES
from tests.transfer_signature.common import ROOT
from trigger_template_interface.canonical import canonical_manifest_bytes, manifest_digest
from trigger_template_interface.manifest import adapt_normalized_template, build_manifest
from trigger_template_interface.validate import validate_manifest


class ManifestTests(unittest.TestCase):
    def test_all_legacy_identity_styles_are_stable(self):
        for name, directory in CASE_TEMPLATES.items():
            with self.subTest(name=name):
                first = adapt_normalized_template(ROOT / directory, repo_root=ROOT)
                second = adapt_normalized_template(ROOT / directory, repo_root=ROOT)
                self.assertEqual(canonical_manifest_bytes(first), canonical_manifest_bytes(second))
                self.assertEqual(manifest_digest(first), manifest_digest(second))
                self.assertEqual(
                    [x["slot_ref"] for x in first["slots"]],
                    [x["slot_ref"] for x in second["slots"]],
                )

    def test_astlite_name_and_mixed_mapping(self):
        astlite = adapt_normalized_template(ROOT / CASE_TEMPLATES["mbedtls_poc_0020"], repo_root=ROOT)
        named = adapt_normalized_template(ROOT / CASE_TEMPLATES["mbedtls_poc_0005"], repo_root=ROOT)
        self.assertTrue(any(ref.startswith("ASTLITE-") for x in astlite["slots"] for ref in x["legacy_source_refs"]))
        self.assertTrue(any(ref.startswith("step") for x in named["slots"] for ref in x["legacy_source_refs"]))
        self.assertTrue(any(x["source_locator"]["line_start"] is not None for x in astlite["slots"]))

    def test_template_digest_changes_linkage(self):
        manifest = adapt_normalized_template(ROOT / CASE_TEMPLATES["mbedtls_poc_0005"], repo_root=ROOT)
        changed = deepcopy(manifest)
        changed["trigger_template_digest"] = "a" * 64
        self.assertNotEqual(canonical_manifest_bytes(manifest), canonical_manifest_bytes(changed))

    def test_duplicate_dangling_and_ambiguous_rejected(self):
        manifest = adapt_normalized_template(ROOT / CASE_TEMPLATES["mbedtls_poc_0005"], repo_root=ROOT)
        duplicate = deepcopy(manifest)
        duplicate["slots"].append(deepcopy(duplicate["slots"][0]))
        duplicate["source_mapping"].append(deepcopy(duplicate["source_mapping"][0]))
        self.assertTrue(any("duplicate slot_ref" in x for x in validate_manifest(duplicate)))
        dangling = deepcopy(manifest)
        dangling["slots"][0]["dependencies"] = ["slot:input:does-not-exist"]
        self.assertTrue(any("dangling slot" in x for x in validate_manifest(dangling)))
        ambiguous = deepcopy(manifest)
        ambiguous["slots"][1]["legacy_source_refs"].append(ambiguous["slots"][0]["legacy_source_refs"][0])
        ambiguous["source_mapping"].append({"slot_ref": ambiguous["slots"][1]["slot_ref"], "legacy_source_ref": ambiguous["slots"][0]["legacy_source_refs"][0]})
        self.assertTrue(any("ambiguous legacy mapping" in x for x in validate_manifest(ambiguous)))

    def test_missing_identity_evidence_rejects_construction(self):
        with self.assertRaisesRegex(ValueError, "missing identity evidence"):
            build_manifest(
                trigger_template_ref="template:TEST", trigger_template_digest="b" * 64,
                units=[{"role": "trigger_call"}], source_artifact_ref="tests/fixture.yaml",
            )


if __name__ == "__main__":
    unittest.main()
