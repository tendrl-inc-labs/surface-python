"""Action-screening context forwarding for scan_payload."""

from __future__ import annotations

import json

import httpx

from surface import SurfaceClient
from surface.models import ActionContext, ActionPayee

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
            known_payees=[ActionPayee(name="Delta", iban="GB29NWBK60161331926819")],
            user_request="pay this month's invoices",
        ),
    )
    ctx = seen.get("context")
    assert ctx, f"no context in body: {seen}"
    assert ctx["user_request"] == "pay this month's invoices"
    assert ctx["allowed_egress"] == ["api.stripe.com", "hooks.slack.com"]
    assert ctx["known_payees"][0]["iban"] == "GB29NWBK60161331926819"
    # exclude_none keeps the payload lean.
    assert "account" not in ctx["known_payees"][0]


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
    known = "GB29NWBK60161331926819"

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        payees = (body.get("context") or {}).get("known_payees") or []
        if any(p.get("iban") == known for p in payees):
            return httpx.Response(200, json=_resp("Clean", "Allow"))
        return httpx.Response(200, json=_resp("Malicious", "Block"))

    payload = '{"tool":"create_payment","args":{"iban":"' + known + '"}}'
    with_ctx = _client(handler).scan_payload(
        payload, context=ActionContext(known_payees=[ActionPayee(name="Delta", iban=known)])
    )
    without = _client(handler).scan_payload(payload)
    assert with_ctx.safety_score.recommended_action == "Allow"
    assert without.safety_score.recommended_action == "Block"
