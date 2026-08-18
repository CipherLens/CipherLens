from __future__ import annotations

import json
import unittest

from binding_proposal.config import CodexExecConfig, GLMConfig, ProviderConfig
from binding_proposal.model import FallbackPolicy, InvocationStatus, PreparedRequest, ProviderInvocationResult, ProviderKind
from binding_proposal.provider import LLMRoleProposalProvider
from binding_proposal.providers.codex_exec import CodexExecProvider, CodexJSONLError, decode_codex_jsonl
from binding_proposal.providers.glm import GLMProvider
from binding_proposal.router import ProviderRouter
from tests.binding_proposal.common import payload


def jsonl(document: dict) -> str:
    return "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "test"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(document)}}),
        json.dumps({"type": "turn.completed"}),
    ])


class ProviderTests(unittest.TestCase):
    def test_codex_command_and_fail_closed_preflight(self):
        provider = CodexExecProvider()
        request = provider.prepare_request("prompt", schema_path="binding_proposal/payload.schema.yaml", invocation_ref="invoke:codex")
        command = provider.build_command(request)
        self.assertIn("read-only", command); self.assertIn("--ephemeral", command); self.assertIn("--json", command)
        self.assertEqual(InvocationStatus.POLICY_REJECTED, provider.invoke(request).status)

    def test_codex_decoder_and_fake_transport(self):
        self.assertEqual(payload(), decode_codex_jsonl(jsonl(payload())))
        cases = (
            ("", "empty"),
            ("not-json", "malformed"),
            (json.dumps({"type": "unknown"}), "unexpected"),
            (json.dumps({"type": "turn.completed"}), "missing"),
            ("\n".join(jsonl(payload()).splitlines()[:-1]), "truncated"),
            (jsonl(payload()) + "\n" + json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(payload())}}), "multiple"),
        )
        for raw, label in cases:
            with self.subTest(label=label), self.assertRaises(CodexJSONLError):
                decode_codex_jsonl(raw)
        config = CodexExecConfig(tool_network_isolation_proven=True)
        provider = CodexExecProvider(config, transport=lambda command, prompt: (0, jsonl(payload()), "stderr-not-parsed"))
        request = provider.prepare_request("prompt", schema_path="schema", invocation_ref="invoke")
        self.assertEqual(InvocationStatus.SUCCESS, provider.invoke(request).status)
        nonzero = CodexExecProvider(config, transport=lambda command, prompt: (9, "", "safe diagnostic"))
        self.assertEqual(InvocationStatus.EXECUTION_ERROR, nonzero.invoke(request).status)
        timeout = CodexExecProvider(config, transport=lambda command, prompt: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(InvocationStatus.TIMEOUT, timeout.invoke(request).status)

    def test_glm_full_document_strict_parser(self):
        provider = GLMProvider(GLMConfig(enabled=True), transport=lambda p, m, k: json.dumps(payload()), environ={"ZHIPUAI_API_KEY": "TEST_API_KEY_DO_NOT_USE"})
        request = provider.prepare_request("p", schema_path="s", invocation_ref="i")
        self.assertEqual(InvocationStatus.SUCCESS, provider.invoke(request).status)
        for raw in ("```json\n{}\n```", "prefix {}", "{} {}", "{"):
            strict = GLMProvider(GLMConfig(enabled=True), transport=lambda p, m, k, value=raw: value, environ={"ZHIPUAI_API_KEY": "TEST_API_KEY_DO_NOT_USE"})
            self.assertEqual(InvocationStatus.INVALID_OUTPUT, strict.invoke(request).status)
        self.assertEqual(InvocationStatus.PROVIDER_UNAVAILABLE, GLMProvider().invoke(request).status)
        self.assertEqual(InvocationStatus.AUTH_FAILED, GLMProvider(GLMConfig(enabled=True), transport=lambda p, m, k: "{}").invoke(request).status)


class FakeProvider(LLMRoleProposalProvider):
    def __init__(self, result: ProviderInvocationResult): self.result = result; self.calls = 0
    def prepare_request(self, prompt, *, schema_path, invocation_ref): return PreparedRequest(invocation_ref, prompt, schema_path)
    def invoke(self, request): self.calls += 1; return self.result
    def parse_output(self, raw_output): return {}
    def build_provenance(self, request, result): return {}


class RouterTests(unittest.TestCase):
    def test_no_silent_paid_fallback(self):
        for status in (InvocationStatus.QUOTA_EXHAUSTED, InvocationStatus.AUTH_FAILED, InvocationStatus.POLICY_REJECTED, InvocationStatus.TIMEOUT, InvocationStatus.PROVIDER_UNAVAILABLE):
            primary = FakeProvider(ProviderInvocationResult(status, ProviderKind.CODEX_EXEC, "i", "FAIL"))
            glm = FakeProvider(ProviderInvocationResult(InvocationStatus.SUCCESS, ProviderKind.GLM_API, "g", "OK", payload=payload()))
            router = ProviderRouter(primary, config=ProviderConfig(), glm_provider=glm)
            router.invoke(PreparedRequest("i", "p", "s"))
            with self.subTest(status=status): self.assertEqual(0, glm.calls)

    def test_explicit_paid_fallback_only(self):
        primary = FakeProvider(ProviderInvocationResult(InvocationStatus.QUOTA_EXHAUSTED, ProviderKind.CODEX_EXEC, "i", "FAIL"))
        glm = FakeProvider(ProviderInvocationResult(InvocationStatus.SUCCESS, ProviderKind.GLM_API, "g", "OK", payload=payload()))
        config = ProviderConfig(fallback_policy=FallbackPolicy.API_FALLBACK_EXPLICITLY_ALLOWED, glm=GLMConfig(enabled=True))
        result = ProviderRouter(primary, config=config, glm_provider=glm).invoke(PreparedRequest("i", "p", "s"))
        self.assertEqual(InvocationStatus.SUCCESS, result.status); self.assertEqual(1, glm.calls)


if __name__ == "__main__":
    unittest.main()
