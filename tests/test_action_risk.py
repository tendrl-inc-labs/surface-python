"""actionRisk parsing and Decision exposure (no live API)."""
import pytest

from surface import ActionRisk, AsyncToolGuard, ToolGuard
from surface.models import ScanResult

RISK = {
    "probability": 0.87,
    "reasons": ["sends data to an undeclared host", "irreversible"],
    "action": "Block",
    "mode": "shadow",
    "calls": 1,
    "modelVersion": "stage1-2026.09",
    "record": {"verb": "send", "target": "external"},
    "futureKey": {"ignored": True},
}


def _data(action="Allow", risk=None) -> dict:
    data = {
        "name": "t.toolcall.json",
        "size": 1,
        "hash": "sha256:x",
        "contentType": "application/json",
        "safetyScore": {
            "score": 100,
            "threatLevel": "Clean",
            "confidence": "High",
            "confidenceScore": 0.9,
            "confidenceReason": "x",
            "primaryThreat": "No threats detected",
            "threatSummary": "No threats detected",
            "enginesUsed": ["Action Screening"],
            "recommendedAction": action,
        },
        "scanTimeMs": 1,
        "timestamp": 0,
    }
    if risk is not None:
        data["actionRisk"] = risk
    return data


class FakeClient:
    def __init__(self, result):
        self._r = result

    def scan_payload(self, payload, label="p", *, context=None):
        return self._r


class AsyncFakeClient(FakeClient):
    async def scan_payload(self, payload, label="p", *, context=None):
        return self._r


def test_parses_action_risk():
    r = ScanResult.model_validate(_data(risk=RISK))
    ar = r.action_risk
    assert isinstance(ar, ActionRisk)
    assert ar.probability == pytest.approx(0.87)
    assert ar.reasons == RISK["reasons"]
    assert (ar.action, ar.mode, ar.calls) == ("Block", "shadow", 1)
    assert ar.model_version == "stage1-2026.09"
    assert ar.record == {"verb": "send", "target": "external"}


def test_absent_action_risk_is_none():
    assert ScanResult.model_validate(_data()).action_risk is None


def test_action_risk_tolerates_missing_keys():
    ar = ScanResult.model_validate(_data(risk={"probability": 0.1})).action_risk
    assert ar.probability == pytest.approx(0.1)
    assert ar.reasons == []
    assert ar.model_version is None and ar.record is None and ar.action is None
    ar = ScanResult.model_validate(_data(risk={"reasons": None})).action_risk
    assert ar.reasons == [] and ar.probability is None


def test_decision_exposes_risk_without_changing_verdict():
    # Engine says Block in shadow; the verdict stays the scan's Allow.
    d = ToolGuard(FakeClient(ScanResult.model_validate(_data("Allow", RISK)))).screen(
        "send", {"to": "x"}
    )
    assert d.action == "Allow" and d.allowed
    assert d.risk_probability == pytest.approx(0.87)
    assert d.risk_reasons == RISK["reasons"]


def test_decision_defaults_without_risk():
    d = ToolGuard(FakeClient(ScanResult.model_validate(_data("Review")))).screen("t", {})
    assert d.action == "Review"
    assert d.risk_probability is None
    assert d.risk_reasons == []


async def test_async_decision_exposes_risk():
    g = AsyncToolGuard(AsyncFakeClient(ScanResult.model_validate(_data("Allow", RISK))))
    d = await g.screen("send", {})
    assert d.action == "Allow"
    assert d.risk_probability == pytest.approx(0.87)
    assert d.risk_reasons == RISK["reasons"]


def test_parses_content_risk():
    from surface import ContentRisk
    data = _data()
    data["contentRisk"] = {"probability": 0.97, "reasons": ["addresses an AI agent and asks it to act"],
                           "action": "Review", "mode": "shadow", "modelVersion": "content-risk-1", "future": 1}
    cr = ScanResult.model_validate(data).content_risk
    assert isinstance(cr, ContentRisk)
    assert cr.probability == pytest.approx(0.97)
    assert (cr.action, cr.mode, cr.model_version) == ("Review", "shadow", "content-risk-1")
    assert cr.reasons == ["addresses an AI agent and asks it to act"]
    assert ScanResult.model_validate(_data()).content_risk is None
