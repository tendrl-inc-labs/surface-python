"""Tests for the tool-call ToolGuard adapter (no live API)."""
import asyncio
import json
import pytest

from surface import (
    ActionContext,
    AsyncToolGuard,
    ToolBlocked,
    ToolGuard,
    ToolNeedsReview,
    jsonl_trace,
    tool_call_json,
)
from surface.models import ScanResult

CTX = ActionContext(
    principal_domains=["acme.io"],
    allowed_egress=["api.stripe.com"],
    user_request="pay the vendor",
)


def _result(action: str, reason: str = "", findings=None) -> ScanResult:
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
    data = {
        "name": "t.toolcall.json",
        "size": 1,
        "hash": "sha256:x",
        "contentType": "application/json",
        "safetyScore": ss,
        "scanTimeMs": 1,
        "timestamp": 0,
    }
    if findings is not None:
        data["actionScreen"] = {"detected": True, "toolCalls": 1, "findings": findings}
    return ScanResult.model_validate(data)


class FakeClient:
    def __init__(self, action, reason="", findings=None):
        self._r = _result(action, reason, findings)
        self.calls = []

    def scan_payload(self, payload, label="p", *, context=None):
        self.calls.append((payload, label, context))
        return self._r


def test_tool_call_json_shape():
    assert tool_call_json("send_payment", {"amount": 10}) == (
        '{"tool": "send_payment", "args": {"amount": 10}}'
    )


@pytest.mark.parametrize("action", ["Allow", "Review", "Block"])
def test_screen_returns_decision(action):
    d = ToolGuard(FakeClient(action, reason="r"), context=CTX).screen("t", {"a": 1})
    assert d.action == action
    assert d.tool == "t"
    assert d.context_present
    assert d.context_fields == {
        "principal_domains": True,
        "allowed_egress": True,
        "user_request": True,
    }
    assert (d.allowed, d.needs_review, d.blocked) == (
        action == "Allow",
        action == "Review",
        action == "Block",
    )


def test_context_optional():
    fc = FakeClient("Allow")
    d = ToolGuard(fc).screen("t", {"a": 1})
    assert d.action == "Allow"
    assert d.context_present is False
    # The only thing sent is who wrote the payload: a guard screens actions.
    assert fc.calls[0][2].model_dump(exclude_none=True) == {"source": "tool_call"}


def test_invalid_context_rejected():
    with pytest.raises(Exception, match="list of strings"):
        ToolGuard(FakeClient("Allow"), context={"principal_domains": "acme.io"}).screen(
            "t", {}
        )


def test_context_and_label_forwarded():
    fc = FakeClient("Allow")
    guard = ToolGuard(
        fc, context=lambda name, args: ActionContext(principal_domains=["acme.io"])
    )
    guard.screen("http_request", {"url": "https://x"})
    payload, label, ctx = fc.calls[0]
    assert '"tool": "http_request"' in payload
    assert label == "http_request.toolcall.json"
    assert ctx.principal_domains == ["acme.io"]


def test_jsonl_trace(tmp_path):
    path = tmp_path / "trace.jsonl"
    seen = []
    guard = ToolGuard(
        FakeClient(
            "Review",
            reason="outside",
            findings=[{"reason": "Sends data to a recipient outside the organization's domains"}],
        ),
        context=CTX,
        on_decision=lambda d: (seen.append(d), jsonl_trace(path)(d)),
    )
    d = guard.screen("send_email", {"to": "ap@maple.com"})
    assert seen == [d]
    rec = json.loads(path.read_text().splitlines()[0])
    assert rec["tool"] == "send_email"
    assert rec["action"] == "Review"
    assert rec["context_present"] is True
    assert rec["context_fields"]["user_request"] is True
    assert "args" not in rec
    assert rec["findings"][0].startswith("Sends data")


def test_wrap_allows_and_runs():
    ran = []

    def transfer(**kw):
        ran.append(kw)
        return "done"

    safe = ToolGuard(FakeClient("Allow"), context=CTX).wrap(transfer)
    assert safe(amount=10) == "done"
    assert ran == [{"amount": 10}]


def test_wrap_blocks_and_does_not_run():
    ran = []

    def transfer(**kw):
        ran.append(kw)

    guard = ToolGuard(
        FakeClient(
            "Block",
            reason="Sends data to a bare-IP address",
            findings=[{"toolName": "transfer", "reason": "Sends data to a bare-IP address", "evidence": "..."}],
        ),
        context=CTX,
    )
    with pytest.raises(ToolBlocked) as ei:
        guard.wrap(transfer)(amount=10)
    assert ran == []  # the tool never executed
    assert ei.value.decision.blocked
    assert "bare-IP" in ei.value.decision.reason
    assert ei.value.decision.findings[0]["toolName"] == "transfer"


def test_review_is_held_by_default():
    # Review means "a person should confirm this", so the simplest integration
    # must not run it. ToolNeedsReview is a ToolBlocked, so older handlers
    # that catch ToolBlocked still stop it.
    ran = []

    def t(**kw):
        ran.append(kw)
        return "ok"

    with pytest.raises(ToolNeedsReview) as ei:
        ToolGuard(FakeClient("Review", reason="needs a look"), context=CTX).wrap(t)(x=1)
    assert isinstance(ei.value, ToolBlocked)
    assert ei.value.decision.needs_review
    assert ran == []


def test_on_review_allow_and_callable():
    def t(**kw):
        return "ok"

    assert ToolGuard(FakeClient("Review"), context=CTX, on_review="allow").wrap(t)(x=1) == "ok"

    seen = []

    def ask(d):
        seen.append(d.action)
        return True

    assert ToolGuard(FakeClient("Review"), context=CTX, on_review=ask).wrap(t)(x=1) == "ok"
    assert seen == ["Review"]
    with pytest.raises(ToolNeedsReview):
        ToolGuard(FakeClient("Review"), context=CTX, on_review=lambda d: False).wrap(t)(x=1)
    # on_review never runs a Block.
    with pytest.raises(ToolBlocked) as ei:
        ToolGuard(FakeClient("Block"), context=CTX, on_review="allow").wrap(t)(x=1)
    assert not isinstance(ei.value, ToolNeedsReview)


def test_block_on_review_still_works():
    def t(**kw):
        return "ok"

    assert ToolGuard(FakeClient("Review"), context=CTX, block_on_review=False).wrap(t)(x=1) == "ok"
    with pytest.raises(ToolBlocked):
        ToolGuard(FakeClient("Review"), context=CTX, block_on_review=True).wrap(t)(x=1)


def test_invalid_guard_options_rejected():
    with pytest.raises(ValueError):
        ToolGuard(FakeClient("Allow"), strictness="stirct")
    with pytest.raises(ValueError):
        ToolGuard(FakeClient("Allow"), on_review="block")


def test_guard_strictness_fills_context_unless_set():
    fake = FakeClient("Allow")
    ToolGuard(fake, strictness="strict").screen("t", {})
    assert fake.calls[-1][2].strictness == "strict"
    ToolGuard(fake, context=CTX, strictness="strict").screen("t", {})
    ctx = fake.calls[-1][2]
    assert (ctx.strictness, ctx.user_request) == ("strict", "pay the vendor")
    ToolGuard(fake, context=ActionContext(strictness="relaxed"), strictness="strict").screen("t", {})
    assert fake.calls[-1][2].strictness == "relaxed"
    d = ToolGuard(fake, strictness="strict").screen("t", {})
    assert d.strictness == "strict"


def test_screen_user_request_fills_only_a_missing_request():
    fake = FakeClient("Allow")
    ToolGuard(fake).screen("t", {}, user_request="delete my drafts")
    assert fake.calls[-1][2].user_request == "delete my drafts"
    ToolGuard(fake, context=CTX).screen("t", {}, user_request="something else")
    assert fake.calls[-1][2].user_request == "pay the vendor"
    ToolGuard(fake).screen("t", {})
    assert fake.calls[-1][2].user_request is None


def test_async_guard_blocks_and_allows():
    class AsyncFake:
        def __init__(self, action):
            self._r = _result(action)

        async def scan_payload(self, payload, label="p", *, context=None):
            return self._r

    async def tool(**kw):
        return "ran"

    blocked = AsyncToolGuard(AsyncFake("Block"), context=CTX).wrap(tool)
    allowed = AsyncToolGuard(AsyncFake("Allow"), context=CTX).wrap(tool)

    async def run_blocked():
        try:
            await blocked(x=1)
            return "no-raise"
        except ToolBlocked:
            return "blocked"

    assert asyncio.run(run_blocked()) == "blocked"
    assert asyncio.run(allowed(x=1)) == "ran"


def test_async_review_held_and_async_policy():
    class AsyncFake:
        def __init__(self, action):
            self._r = _result(action)

        async def scan_payload(self, payload, label="p", *, context=None):
            return self._r

    async def t(**kw):
        return "ok"

    async def ask(d):
        return True

    async def run():
        with pytest.raises(ToolNeedsReview):
            await AsyncToolGuard(AsyncFake("Review")).wrap(t)(x=1)
        assert await AsyncToolGuard(AsyncFake("Review"), on_review=ask).wrap(t)(x=1) == "ok"

    asyncio.run(run())


def test_guard_marks_source_tool_call_without_overriding():
    fake = FakeClient("Allow")
    ToolGuard(fake, context=CTX).screen("t", {})
    assert fake.calls[-1][2].source == "tool_call"
    ToolGuard(fake, context={"source": "content"}).screen("t", {})
    assert fake.calls[-1][2].source == "content"
