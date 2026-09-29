"""Pydantic AI drop-in guard wiring (skipped unless pydantic-ai is installed).

These tests exercise the documented Hooks.before_tool_execute mapping against
pydantic-ai's TestModel and a fake Surface client — no live scanner or API key.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent, DeferredToolRequests, RunContext, ToolDefinition
from pydantic_ai.capabilities import Hooks, ValidatedToolArgs
from pydantic_ai.exceptions import ApprovalRequired, ToolFailed
from pydantic_ai.messages import ToolCallPart, ToolReturnPart
from pydantic_ai.models.test import TestModel

from surface import ActionContext, AsyncToolGuard
from surface.models import ScanResult


def _result(action: str, reason: str = "") -> ScanResult:
    ss = {
        "score": 100 if action == "Allow" else 25,
        "threatLevel": {"Allow": "Clean", "Review": "Suspicious", "Block": "Malicious"}[action],
        "confidence": "High",
        "confidenceScore": 0.9,
        "confidenceReason": "x",
        "primaryThreat": reason or "No threats detected",
        "threatSummary": reason or "No threats detected",
        "enginesUsed": ["Action Screening"],
        "recommendedAction": action,
    }
    return ScanResult.model_validate(
        {
            "name": "t.toolcall.json",
            "size": 1,
            "hash": "sha256:x",
            "contentType": "application/json",
            "safetyScore": ss,
            "scanTimeMs": 1,
            "timestamp": 0,
        }
    )


class AsyncFake:
    def __init__(self, action: str, reason: str = ""):
        self._r = _result(action, reason)
        self.calls: list[tuple] = []

    async def scan_payload(self, payload, label="p", *, context=None):
        self.calls.append((payload, label, context))
        return self._r


def _agent(fake: AsyncFake, ran: list):
    hooks = Hooks()
    guard = AsyncToolGuard(
        fake,
        context=lambda name, args: ActionContext(
            principal_domains=["acme.io"],
            allowed_egress=["api.stripe.com"],
            user_request="pay the vendor",
        ),
    )

    @hooks.on.before_tool_execute
    async def surface_guard(
        ctx: RunContext,
        *,
        call: ToolCallPart,
        tool_def: ToolDefinition,
        args: ValidatedToolArgs,
    ) -> ValidatedToolArgs:
        d = await guard.screen(call.tool_name, args)
        if d.blocked:
            raise ToolFailed(d.reason)
        if d.needs_review:
            raise ApprovalRequired()
        return args

    agent = Agent(
        TestModel(),
        capabilities=[hooks],
        output_type=[str, DeferredToolRequests],
    )

    @agent.tool_plain
    def transfer_funds(to: str, amount: int) -> str:
        ran.append({"to": to, "amount": amount})
        return f"sent {amount} to {to}"

    return agent


def test_pydantic_ai_allow_runs_the_tool():
    ran: list = []
    fake = AsyncFake("Allow")
    agent = _agent(fake, ran)

    result = agent.run_sync("send the payment")
    assert ran == [{"to": "a", "amount": 0}]  # TestModel fills schema defaults
    assert fake.calls, "guard must screen before the tool runs"
    payload, label, ctx = fake.calls[0]
    assert '"tool": "transfer_funds"' in payload
    assert label == "transfer_funds.toolcall.json"
    assert ctx.principal_domains == ["acme.io"]
    assert "sent 0 to a" in str(result.output)


def test_pydantic_ai_block_does_not_run_the_tool():
    ran: list = []
    fake = AsyncFake("Block", reason="Sends data to a bare-IP address")
    agent = _agent(fake, ran)

    result = agent.run_sync("send the payment")
    assert ran == []
    assert fake.calls, "the call was still screened"
    returns = [
        p
        for m in result.all_messages()
        for p in getattr(m, "parts", [])
        if isinstance(p, ToolReturnPart)
    ]
    assert returns
    assert "bare-IP" in str(returns[0].content)


def test_pydantic_ai_review_defers_for_human():
    ran: list = []
    fake = AsyncFake("Review", reason="Unknown egress host")
    agent = _agent(fake, ran)

    result = agent.run_sync("send the payment")
    assert ran == []
    assert isinstance(result.output, DeferredToolRequests)
    assert result.output.approvals
    assert result.output.approvals[0].tool_name == "transfer_funds"


# ---- surface.pydantic_ai.surface_hooks --------------------------------------

from surface.pydantic_ai import prompt_text, surface_hooks  # noqa: E402


class RecordingFake(AsyncFake):
    async def scan_payload(self, payload, label="p", *, context=None):
        self.calls.append((payload, label, context))
        return self._r


def _hooked_agent(guard, ran):
    agent = Agent(TestModel(), capabilities=[surface_hooks(guard)],
                  output_type=[str, DeferredToolRequests])

    @agent.tool_plain
    def send_email(to: str, body: str) -> str:
        ran.append(to)
        return f"sent to {to}"

    return agent


def test_surface_hooks_sends_run_prompt_as_user_request():
    fake, ran = RecordingFake("Allow"), []
    agent = _hooked_agent(AsyncToolGuard(fake), ran)
    agent.run_sync("Email wen@acme.io the weekly summary")
    assert ran, "Allow must let the tool run"
    assert fake.calls[0][2].user_request == "Email wen@acme.io the weekly summary"


def test_surface_hooks_keeps_an_explicit_user_request():
    fake, ran = RecordingFake("Allow"), []
    guard = AsyncToolGuard(fake, context=ActionContext(user_request="the user's own words"))
    _hooked_agent(guard, ran).run_sync("prompt built from a retrieved document")
    assert fake.calls[0][2].user_request == "the user's own words"


def test_surface_hooks_defers_review_and_fails_block():
    ran = []
    out = _hooked_agent(AsyncToolGuard(RecordingFake("Review")), ran).run_sync("x")
    assert isinstance(out.output, DeferredToolRequests) and ran == []
    ran = []
    _hooked_agent(AsyncToolGuard(RecordingFake("Block", "exfil")), ran).run_sync("x")
    assert ran == []


def test_surface_hooks_respects_on_review_allow():
    ran = []
    _hooked_agent(AsyncToolGuard(RecordingFake("Review"), on_review="allow"), ran).run_sync("x")
    assert ran


def test_prompt_text_joins_string_parts():
    assert prompt_text("hi") == "hi"
    assert prompt_text(["a", object(), "b"]) == "a\nb"
    assert prompt_text(None) is None
