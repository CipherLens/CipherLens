import unittest
from pathlib import Path
from real_campaign_bridge.c1_fix6 import overlay, resolution

class C1Fix6Test(unittest.TestCase):
 def test_overlay_resolves_values_but_capture_protocol_stays_blocked(self):
  o=overlay(Path(__file__).resolve().parents[2]); r=resolution(Path(__file__).resolve().parents[2],o)
  self.assertEqual(5,len(o["deterministic_value_holes"])); self.assertEqual("COMPLETE",r["status"])
  self.assertEqual("manifest:4a467287487af1a7bc4e9690bc3b450b0ebf774de4b2ae34593e579f2f3f8b8b",o["parent_template_interface"]["ref"])
