from __future__ import annotations

from pathlib import Path
import unittest

import yaml

from candidate_binding.canonical import canonical_candidate_binding_bytes, canonical_validation_bytes
from candidate_binding.registry import validate_with_registry
from tests.candidate_binding.common import case_context
from tests.transfer_signature.common import ROOT
from trigger_template_interface.canonical import canonical_manifest_bytes


class GoldenTests(unittest.TestCase):
    def test_three_family_artifacts_are_reproducible(self):
        base = ROOT / "tests" / "candidate_binding" / "fixtures" / "golden"
        for name in ("mbedtls_poc_0020", "mbedtls_poc_0004", "mbedtls_poc_0005"):
            directory = base / name; context = case_context(name)
            manifest = yaml.safe_load((directory / "template_interface.manifest.yaml").read_text())
            self.assertEqual(canonical_manifest_bytes(context.template_manifest), canonical_manifest_bytes(manifest))
            for label, expected in (("valid", "VALID"), ("invalid", "INVALID"), ("incomplete", "INCOMPLETE")):
                binding = yaml.safe_load((directory / f"{label}.binding.yaml").read_text())
                validation = yaml.safe_load((directory / f"{label}.validation.yaml").read_text())
                actual = validate_with_registry(binding, context)
                with self.subTest(name=name, label=label):
                    self.assertEqual(expected, validation["status"])
                    self.assertEqual(canonical_validation_bytes(validation), canonical_validation_bytes(actual))
                    canonical_candidate_binding_bytes(binding)


if __name__ == "__main__": unittest.main()
