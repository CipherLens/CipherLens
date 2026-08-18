"""Regenerate deterministic CandidateBinding foundation fixtures."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import yaml

from candidate_binding.registry import validate_with_registry
from tests.candidate_binding.common import rebuild, valid_case


ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "candidate_binding" / "fixtures" / "golden"
CASES = ("mbedtls_poc_0020", "mbedtls_poc_0004", "mbedtls_poc_0005")


def main() -> None:
    for name in CASES:
        binding, context, validation = valid_case(name)
        invalid = deepcopy(binding)
        original = invalid["subject_bindings"][0]
        alternative = next(
            subject for subject in context.target_profile["subjects"]
            if subject["subject_ref"] != original["target_subject_ref"]
        )
        original["target_subject_ref"] = alternative["subject_ref"]
        invalid = rebuild(invalid)
        invalid_validation = validate_with_registry(invalid, context)

        incomplete = deepcopy(binding)
        incomplete["operation_bindings"][0]["verified_fact_refs"] = [
            "F_MISSING_REQUIRED_VERIFIED_EVIDENCE"
        ]
        incomplete = rebuild(incomplete)
        incomplete_validation = validate_with_registry(incomplete, context)

        directory = GOLDEN / name
        directory.mkdir(parents=True, exist_ok=True)
        documents = {
            "template_interface.manifest.yaml": context.template_manifest,
            "valid.binding.yaml": binding,
            "valid.validation.yaml": validation,
            "invalid.binding.yaml": invalid,
            "invalid.validation.yaml": invalid_validation,
            "incomplete.binding.yaml": incomplete,
            "incomplete.validation.yaml": incomplete_validation,
        }
        for filename, document in documents.items():
            (directory / filename).write_text(
                yaml.safe_dump(document, allow_unicode=True, sort_keys=True), encoding="utf-8"
            )


if __name__ == "__main__":
    main()
