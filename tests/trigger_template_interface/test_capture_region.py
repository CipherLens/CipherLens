import copy
import unittest

from trigger_template_interface.capture_region import (
    CAPTURE_REGION_ID,
    capture_region_digest,
    make_capture_region_overlay,
    make_declared_capture_region,
    validate_declared_capture_region,
)


SHA = "1" * 64
PARENT = {"ref": "manifest:parent", "digest": "2" * 64}


def region():
    return make_declared_capture_region(
        capture_region_id=CAPTURE_REGION_ID,
        template_ref="template:test",
        template_digest=SHA,
        source_region_ref=CAPTURE_REGION_ID,
        semantic_roles=["operation_outcome", "consumed_length", "input_length"],
        phase="AFTER_STEP",
        operation_ref="OPERATION_0_PARSE_KEY",
        multiplicity="ONE_OR_MORE",
        provenance_refs=[PARENT],
    )


class DeclaredCaptureRegionTests(unittest.TestCase):
    def test_overlay_requires_template_parent(self):
        with self.assertRaises(ValueError):
            make_capture_region_overlay(
                parent_ref="", parent_digest=PARENT["digest"],
                template_ref="template:test", template_digest=SHA,
                capture_regions=[region()],
            )

    def test_protected_region_is_rejected(self):
        value = region()
        value["protected"] = True
        value["digest"] = capture_region_digest(value)
        with self.assertRaises(ValueError):
            validate_declared_capture_region(value)

    def test_digest_is_stable_and_changes_with_semantics(self):
        first = region()
        second = region()
        self.assertEqual(first, second)
        changed = copy.deepcopy(first)
        changed["multiplicity"] = "ONE"
        changed["digest"] = capture_region_digest(changed)
        self.assertNotEqual(first["digest"], changed["digest"])

    def test_overlay_does_not_mutate_region_or_parent(self):
        value = region()
        before = copy.deepcopy(value)
        overlay = make_capture_region_overlay(
            parent_ref=PARENT["ref"], parent_digest=PARENT["digest"],
            template_ref="template:test", template_digest=SHA,
            capture_regions=[value],
        )
        self.assertEqual(before, value)
        self.assertFalse(overlay["base_manifest_modified"])
