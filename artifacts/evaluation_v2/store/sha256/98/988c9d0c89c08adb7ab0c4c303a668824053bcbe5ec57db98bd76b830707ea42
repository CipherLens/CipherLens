from __future__ import annotations

from copy import deepcopy
import unittest

from binding_proposal.canonical import build_binding_proposal, binding_proposal_digest, canonical_binding_proposal_bytes, canonical_payload_bytes
from binding_proposal.model import InvocationStatus
from binding_proposal.providers.replay import ReplayProposalProvider
from binding_proposal.validate import validate_binding_proposal, validate_payload
from tests.binding_proposal.common import payload, reference


class ProposalSchemaTests(unittest.TestCase):
    def test_payload_unknown_trusted_and_secret_fields_rejected(self):
        for key, value in (("unknown", True), ("verified", True), ("eligible", True), ("verdict", "VIOLATED"), ("api_key", "TEST_API_KEY_DO_NOT_USE")):
            candidate = payload(); candidate[key] = value
            with self.subTest(key=key):
                self.assertTrue(validate_payload(candidate))

    def test_natural_language_is_not_a_lexical_blacklist(self):
        candidate = payload()
        candidate["advisory_rationale"] = "Not verified; eligibility and verdict remain deterministic decisions."
        self.assertEqual([], validate_payload(candidate))

    def test_trusted_envelope_is_program_injected_and_stable(self):
        provider = ReplayProposalProvider(payload())
        request = provider.prepare_request("prompt", schema_path="binding_proposal/payload.schema.yaml", invocation_ref="invoke:1")
        result = provider.invoke(request)
        proposal = build_binding_proposal(
            result.payload, source_references=[reference("tests/source.yaml")],
            target_references=[reference("tests/target.yaml")], provider_provenance=provider.build_provenance(request, result),
            evidence=[],
        )
        self.assertEqual("PROPOSED", proposal["epistemic_status"])
        self.assertEqual([], validate_binding_proposal(proposal))
        shuffled = deepcopy(proposal)
        shuffled["operation_proposals"][0]["related_refs"].append("subject:synthetic-parser")
        self.assertEqual(canonical_binding_proposal_bytes(proposal), canonical_binding_proposal_bytes(shuffled))
        self.assertEqual(binding_proposal_digest(proposal), binding_proposal_digest(shuffled))
        changed = deepcopy(proposal); changed["operation_proposals"][0]["target_ref"] = "symbol:other"
        self.assertNotEqual(binding_proposal_digest(proposal), binding_proposal_digest(changed))

    def test_payload_canonical_order(self):
        candidate = payload()
        second = deepcopy(candidate["operation_proposals"][0]); second["proposal_ref"] = "proposal-item:operation:0"
        candidate["operation_proposals"].append(second)
        reversed_candidate = deepcopy(candidate); reversed_candidate["operation_proposals"].reverse()
        self.assertEqual(canonical_payload_bytes(candidate), canonical_payload_bytes(reversed_candidate))

    def test_replay_malformed_and_schema_rejected(self):
        request = ReplayProposalProvider("{").prepare_request("x", schema_path="x", invocation_ref="i")
        self.assertEqual(InvocationStatus.INVALID_OUTPUT, ReplayProposalProvider("{").invoke(request).status)
        invalid = payload(); invalid["trusted"] = True
        self.assertEqual(InvocationStatus.SCHEMA_REJECTED, ReplayProposalProvider(invalid).invoke(request).status)


if __name__ == "__main__":
    unittest.main()
