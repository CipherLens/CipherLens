from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from real_campaign_bridge.build_profile import make_build_environment_profile
from real_campaign_bridge.capture_bridge import OracleEventStatus, event_line, make_oracle_event, parse_oracle_event, runner_compat_projection
from real_campaign_bridge.claim_gate_adapter import evaluate_preflight
from real_campaign_bridge.differential_pair import make_differential_pair_manifest
from real_campaign_bridge.evidence_root import EvidenceRoot
from real_campaign_bridge.population_manifest import make_population_manifest
from real_campaign_bridge.target_adaptation import adapt_target_source


class RealCampaignBridgeTests(unittest.TestCase):
    DIGEST = "a" * 64

    def _profile(self, revision="buggy"):
        return make_build_environment_profile(source_root={"ref": "source:mbedtls:0020", "digest": self.DIGEST}, source_identity="source:mbedtls:0020", source_tree_digest=self.DIGEST, compiler_identity={"name": "cc", "version_digest": self.DIGEST}, architecture="x86_64", build_system_config={"digest": self.DIGEST}, compile_flags=["-O0"], link_flags=[], include_roots=["include:mbedtls"], library_inputs=[{"ref": "library:mbedtls", "digest": self.DIGEST}], artifact_outputs=["artifact:binary"], sanitizer_profile="none", dependencies=[], controlled_environment="local-inventory", timeout_seconds=30, target_options={}, input_artifact_digests=[self.DIGEST], reproducibility_status="INVENTORIED", source_revision=revision)

    def _pair(self, buggy, fixed):
        ref = {"ref": "ref:x", "digest": self.DIGEST}
        return make_differential_pair_manifest(buggy_profile=buggy, fixed_profile=fixed, case_id="0020", family="rsa_der", buggy_source=ref, fixed_source=ref, fix=ref, contract=ref, transfer_signature=ref, template=ref, input_artifact=ref, observation_schema_refs=["schema:observation"], fix_required_change="fix")

    def _binding(self, symbol_ref="symbol:openssl:3.5.5:d2i_RSAPrivateKey", status="VALID"):
        return {"binding_id": "binding:x", "validation_status": status, "target_symbol_ref": symbol_ref, "operation_binding_ref": "operation-binding:x", "input_binding_ref": "input-binding:x", "observation_binding_refs": ["observation-binding:x"], "target_scope": {"library": "OpenSSL", "version": "3.5.5", "surface_ref": "surface:openssl:3.5.5"}}

    def _merge(self):
        return {"merge_id": "merge:x", "operation_mapping_ref": "operation-map:x", "input_mapping_ref": "input-map:x", "observation_mapping_refs": ["observation-map:x"]}

    def _evidence(self):
        contract = {"ref": "contracts/0020.vc.yaml", "digest": self.DIGEST}
        pair = {"ref": "differential_pairs/0020.json", "digest": "b" * 64}
        openssl = {"ref": "target_knowledge/openssl.json", "digest": "c" * 64}
        wolf = {"ref": "target_knowledge/wolfssl.json", "digest": "d" * 64}
        return {case: {"contract": {**contract, "ref": f"contracts/{case}.vc.yaml"}, "pair": {**pair, "ref": f"differential_pairs/{case}.json"}, "openssl_profile": openssl, "wolfssl_profile": wolf} for case in ("0020", "0004", "0005")}

    def test_rsa_adaptation_declares_required_holes(self):
        result = adapt_target_source(self._merge(), self._binding())
        self.assertIn("hole:d2i_RSAPrivateKey:input_length", result["unresolved_hole_refs"])
        self.assertIn("cursor", result["source"])
        self.assertFalse(result["execution_eligible"])

    def test_cipher_adaptation_requires_outl_before_and_after(self):
        result = adapt_target_source(self._merge(), self._binding("symbol:openssl:3.5.5:EVP_DecryptFinal_ex"))
        self.assertIn("hole:EVP_DecryptFinal_ex:outl_before_observation", result["unresolved_hole_refs"])
        self.assertIn("int outl_before", result["source"])

    def test_adaptation_rejects_invalid_or_absent_binding(self):
        self.assertEqual(adapt_target_source(self._merge(), None)["adaptation_status"], "REJECTED")
        self.assertEqual(adapt_target_source(self._merge(), self._binding(status="PENDING"))["adaptation_status"], "REJECTED")
        self.assertEqual(adapt_target_source(self._merge(), self._binding(), {"invented": "x"})["adaptation_status"], "INCOMPLETE")

    def test_adaptation_never_uses_serialized_text_as_symbol_fallback(self):
        binding = self._binding()
        binding.pop("target_symbol_ref")
        binding["rationale"] = "d2i_RSAPrivateKey appears here but is not a binding"
        result = adapt_target_source(self._merge(), binding)
        self.assertEqual(result["adaptation_status"], "INCOMPLETE")
        self.assertNotIn("source", result)

    def test_event_status_is_not_a_verdict(self):
        event = make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="operation_outcome", acquisition_kind="return", phase="after", subject_ref="s", operation_ref="op", correlation_group_ref="g", status=OracleEventStatus.OBSERVED_ABSENCE.value, value_type="int")
        self.assertEqual(event["verdict_authority"], "NONE")
        self.assertFalse(runner_compat_projection(event)["value_presence"])

    def test_event_round_trip(self):
        event = make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="output_length", acquisition_kind="memory", phase="after", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="PRESENT", value_type="int", value=0)
        self.assertEqual(parse_oracle_event(event_line(event))["event_digest"], event["event_digest"])

    def test_invalid_event_role_fails_closed(self):
        with self.assertRaises(ValueError):
            make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="sanitizer", acquisition_kind="stderr", phase="after", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="PRESENT", value_type="text")

    def test_channel_unavailable_never_projects_as_active(self):
        event = make_oracle_event(witness_ref="w", contract_observable_ref="o", observation_binding_ref="b", merge_capture_ref="m", semantic_role="fatal_event", acquisition_kind="signal", phase="after", subject_ref="s", operation_ref="op", correlation_group_ref="g", status="CHANNEL_UNAVAILABLE", value_type="none")
        self.assertFalse(runner_compat_projection(event)["channel_active"])

    def test_pair_allows_only_revision_difference(self):
        pair = self._pair(self._profile("buggy"), self._profile("fixed"))
        self.assertEqual(pair["allowed_difference_axes"], ["source_revision", "fix_required_change"])
        changed = self._profile("fixed")
        changed["compile_flags"] = ["-O2"]
        with self.assertRaises(ValueError):
            self._pair(self._profile(), changed)

    def test_population_is_exactly_eleven_and_retains_negative_tracks(self):
        manifest = make_population_manifest(self._evidence())
        self.assertEqual(len(manifest["units"]), 11)
        self.assertEqual(manifest["campaign_id"], "CLV2-RQ4-PILOT-001")
        self.assertTrue(any("MATCHER_NO_MATCH" in unit["expected_terminal_states"] for unit in manifest["units"]))
        self.assertTrue(all(len(item["digest"]) == 64 for unit in manifest["units"] for item in ([{"digest": unit["source_contract_digest"]}] + ([{"digest": unit["source_pair_digest"]}] if unit["source_pair_digest"] else []) + ([{"digest": unit["target_profile_digest"]}] if unit["target_profile_digest"] else []))))
        self.assertTrue(all(unit["missing_artifacts"] for unit in manifest["units"]))

    def test_population_rejects_non_sha_artifact_edge(self):
        evidence = self._evidence()
        evidence["0020"]["contract"]["digest"] = "0" * 63
        with self.assertRaises(ValueError):
            make_population_manifest(evidence)

    def test_evidence_root_is_create_only(self):
        with tempfile.TemporaryDirectory() as path:
            root = EvidenceRoot(Path(path))
            edge = root.write_json("safe/a.json", {"x": 1})
            self.assertEqual(edge["digest"], hashlib.sha256((Path(path) / "safe/a.json").read_bytes()).hexdigest())
            root.write_json("safe/a.json", {"x": 1})
            with self.assertRaises(FileExistsError):
                root.write_json("safe/a.json", {"x": 2})

    def test_preflight_is_not_c_ready(self):
        manifest = make_population_manifest(self._evidence())
        output = evaluate_preflight(target_profiles=[{"validation_status": "PREPARED"}], population_manifest=manifest)
        self.assertEqual(output["status"], "PREPARED_FOR_7D_B0_FOUNDATION")
        self.assertIn("NO_REAL_EXECUTION_TRACE", output["blocking_reasons"])

    def test_v2_adaptation_has_no_legacy_free_form_filler_import(self):
        source = (Path(__file__).parents[2] / "real_campaign_bridge" / "target_adaptation.py").read_text(encoding="utf-8")
        self.assertNotIn("adapter_filler", source)

    def test_build_profile_rejects_missing_or_fake_library_digest(self):
        fields = dict(self._profile())
        fields.pop("profile_id")
        fields["library_inputs"] = [{"ref": "library:x", "digest": "p" + "ending"}]
        with self.assertRaises(ValueError):
            make_build_environment_profile(**fields)

    def test_bridge_has_no_network_or_provider_transport_import(self):
        root = Path(__file__).parents[2] / "real_campaign_bridge"
        source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
        for forbidden in ("requests", "urllib", "socket", "CodexExecProvider", "GLM"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
