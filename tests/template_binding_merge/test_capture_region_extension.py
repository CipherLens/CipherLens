import json
import unittest
from pathlib import Path

from real_campaign_bridge.capture_emitter import capture_emitter_binding
from template_binding_merge.capture_region import (
    make_merge_capture_binding,
    make_source_map_capture_extension,
)
from trigger_template_interface.capture_region import (
    CAPTURE_REGION_ID,
    make_capture_region_overlay,
    make_declared_capture_region,
)


ROOT = Path(__file__).resolve().parents[2]
LINEAGE = ROOT / "artifacts/pipeline_v2/single_unit_dry_run/repairs/c1-fix2-v0.1/lineage"


def inputs():
    merge = json.loads((LINEAGE / "merge.json").read_text())
    source_map = json.loads((LINEAGE / "source_map.json").read_text())
    parent = {"ref": merge["trigger_template_interface_ref"], "digest": merge["trigger_template_interface_digest"]}
    region = make_declared_capture_region(
        capture_region_id=CAPTURE_REGION_ID,
        template_ref=merge["trigger_template_ref"],
        template_digest=merge["trigger_template_digest"],
        source_region_ref=CAPTURE_REGION_ID,
        semantic_roles=["operation_outcome", "consumed_length", "input_length"],
        phase="AFTER_STEP",
        operation_ref="OPERATION_0_PARSE_KEY",
        multiplicity="ONE_OR_MORE",
        provenance_refs=[parent],
    )
    overlay = make_capture_region_overlay(
        parent_ref=parent["ref"], parent_digest=parent["digest"],
        template_ref=merge["trigger_template_ref"],
        template_digest=merge["trigger_template_digest"], capture_regions=[region],
    )
    binding = make_merge_capture_binding(
        merge, region, emitter_ref="runtime_event/emitter.py", emitter_digest="3" * 64,
    )
    return merge, source_map, region, overlay, binding


class CaptureRegionExtensionTests(unittest.TestCase):
    def test_merge_binding_requires_declared_region(self):
        merge, _, region, _, _ = inputs()
        region["protected"] = True
        with self.assertRaises(ValueError):
            make_merge_capture_binding(
                merge, region, emitter_ref="runtime_event/emitter.py", emitter_digest="3" * 64,
            )

    def test_source_map_without_capture_region_is_rejected(self):
        merge, source_map, _, overlay, binding = inputs()
        overlay["capture_regions"] = []
        with self.assertRaises(ValueError):
            make_source_map_capture_extension(source_map, merge, overlay, binding)

    def test_template_identity_mismatch_is_rejected(self):
        merge, source_map, _, overlay, binding = inputs()
        overlay["template_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            make_source_map_capture_extension(source_map, merge, overlay, binding)

    def test_source_map_extension_preserves_base_map(self):
        merge, source_map, _, overlay, binding = inputs()
        extension = make_source_map_capture_extension(source_map, merge, overlay, binding)
        self.assertEqual("READY", extension["status"])
        self.assertTrue(extension["base_source_map_unchanged"])
        self.assertFalse(extension["protected_regions_modified"])
        self.assertEqual(3, len(extension["capture_links"]))

    def test_runtime_emitter_requires_region(self):
        capture = {
            "capture_binding_id": "capture:test",
            "observation_binding_ref": "observation:test",
            "semantic_role": "input_length",
            "acquisition_kind": "BOUND_VALUE",
            "phase": "AFTER_STEP",
        }
        self.assertEqual(
            "MISSING_DECLARED_CAPTURE_REGION",
            capture_emitter_binding(capture, [])["status"],
        )
        _, _, region, _, _ = inputs()
        self.assertEqual("READY", capture_emitter_binding(capture, [region])["status"])
