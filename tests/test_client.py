"""Tests for the Surface Python SDK client.

Covers the correctness fixes:
- usage parsing against the real /account/usage field names
- case-insensitive reject matching against the capitalized ThreatLevel
- the scan-history path (/account/history, not /account/scans)
- request_id sent as the X-Request-ID header (not a query param)
- the default base URL pointing at the real service base
"""

from __future__ import annotations

import copy

import httpx
import pytest

from surface import AsyncSurfaceClient, MaliciousFileError, SurfaceClient
from surface.models import Usage

# A scan response whose ThreatLevel is capitalized, exactly as the backend emits.
SCAN_RESPONSE = {
    "name": "sample.exe",
    "size": 10,
    "hash": "abc123",
    "contentType": "application/octet-stream",
    "safetyScore": {
        "score": 5,
        "threatLevel": "Malicious",
        "confidence": "High",
        "confidenceScore": 0.95,
        "confidenceReason": "",
        "primaryThreat": "trojan",
        "threatSummary": "",
        "enginesUsed": [],
        "recommendedAction": "Block",
        "coverage": "full",
    },
    "scanTimeMs": 1,
    "timestamp": 0,
}

# A minimal-coverage response: a JAR the engines cleared, which the backend caps
# at Informational because no ML model covers JVM bytecode.
MINIMAL_COVERAGE_RESPONSE = {
    "name": "app.jar",
    "size": 4096,
    "hash": "def456",
    "contentType": "application/java-archive",
    "safetyScore": {
        "score": 85,
        "threatLevel": "Informational",
        "confidence": "Medium",
        "confidenceScore": 0.6,
        "confidenceReason": "",
        "primaryThreat": "No threats detected",
        "threatSummary": "",
        "enginesUsed": ["YARA"],
        "recommendedAction": "Allow",
        "coverage": "minimal",
        "coverageNote": "Archive of JVM or Android bytecode.",
    },
    "scanTimeMs": 1,
    "timestamp": 0,
}

# The actual shape returned by GET /account/usage.
USAGE_RESPONSE = {
    "scans_used": 5,
    "max_scans": 100,
    "scans_remaining": 95,
    "max_file_size_mb": 10,
    "plan_tier": "free",
    "reset_at": "2026-07-01",
    "daily_volume": {"dates": ["2026-06-15"], "counts": [5]},
}

HISTORY_RESPONSE = {
    "scans": [],
    "total": 0,
    "page": 1,
    "limit": 25,
    "has_more": False,
}


def _make_client(handler) -> SurfaceClient:
    client = SurfaceClient(api_key="sfk_test")
    client._client = httpx.Client(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )
    return client


def test_default_base_url_is_real_service_base():
    client = SurfaceClient(api_key="sfk_test")
    assert client.base_url == "https://app.tendrl.com/surface/api"


def test_usage_parses_backend_field_names():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/account/usage")
        return httpx.Response(200, json=USAGE_RESPONSE)

    usage = _make_client(handler).get_usage()
    assert isinstance(usage, Usage)
    assert usage.scans_used == 5
    assert usage.max_scans == 100
    assert usage.scans_remaining == 95
    assert usage.max_file_size_mb == 10
    assert usage.plan_tier == "free"
    assert usage.daily_volume is not None
    assert usage.daily_volume.counts == [5]


def test_usage_rejects_legacy_credits_schema():
    # The old credits_*/monthly_credits/tiers shape must no longer validate.
    with pytest.raises(Exception):
        Usage.model_validate(
            {
                "credits_used": 1,
                "monthly_credits": 2,
                "credits_remaining": 3,
                "credits_reset_at": "x",
                "tiers": {},
            }
        )


def test_scan_history_uses_history_path():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        return httpx.Response(200, json=HISTORY_RESPONSE)

    _make_client(handler).get_scan_history(page=1, limit=25)
    assert captured["path"].endswith("/account/history")
    assert not captured["path"].endswith("/account/scans")


def test_reject_matches_case_insensitively():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SCAN_RESPONSE)

    client = _make_client(handler)
    # lowercase "malicious" must match the server's capitalized "Malicious".
    with pytest.raises(MaliciousFileError):
        client.scan_file(b"payload", reject=["malicious"])


def test_reject_does_not_falsely_match_other_levels():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SCAN_RESPONSE)

    client = _make_client(handler)
    # Rejecting only "clean" must NOT raise for a Malicious file.
    result = client.scan_file(b"payload", reject=["clean"])
    assert result.safety_score.threat_level == "Malicious"


def test_reject_matches_recommended_action():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SCAN_RESPONSE)

    client = _make_client(handler)
    # "Block" is a recommended action, not a threat level — reject must still match.
    with pytest.raises(MaliciousFileError):
        client.scan_file(b"payload", reject=["Block"])


def test_scan_decorator_rejects_on_recommended_action():
    from surface import scan

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=SCAN_RESPONSE)

    ran = []

    @scan(client=_make_client(handler), reject=["Block"])
    def process(result):
        ran.append(result)

    with pytest.raises(MaliciousFileError):
        process(b"payload")
    assert ran == []  # handler must not run for a rejected file


def test_request_id_sent_as_header_not_query():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["xrid"] = request.headers.get("X-Request-ID", "")
        captured["query"] = request.url.query.decode()
        return httpx.Response(200, json=SCAN_RESPONSE)

    client = _make_client(handler)
    client.scan_file(b"payload", request_id="req-abc-123")
    assert captured["xrid"] == "req-abc-123"
    assert "request_id" not in captured["query"]


@pytest.mark.asyncio
async def test_async_reject_and_history_path():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        if request.url.path.endswith("/account/history"):
            return httpx.Response(200, json=HISTORY_RESPONSE)
        return httpx.Response(200, json=SCAN_RESPONSE)

    client = AsyncSurfaceClient(api_key="sfk_test")
    client._client = httpx.AsyncClient(
        base_url=client.base_url,
        transport=httpx.MockTransport(handler),
    )

    await client.get_scan_history()
    assert captured["path"].endswith("/account/history")

    with pytest.raises(MaliciousFileError):
        await client.scan_file(b"payload", reject=["MALICIOUS"])

    await client.close()


def test_coverage_fields_survive_deserialisation():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=MINIMAL_COVERAGE_RESPONSE)

    result = _make_client(handler).scan_file(b"PK\x03\x04")
    assert result.safety_score.coverage == "minimal"
    assert result.safety_score.coverage_note
    # A minimal scan must never claim Clean.
    assert result.safety_score.threat_level != "Clean"


def test_response_without_coverage_still_parses():
    # An older deployment omits the field entirely; the SDK must not reject it.
    legacy = copy.deepcopy(SCAN_RESPONSE)
    del legacy["safetyScore"]["coverage"]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=legacy)

    result = _make_client(handler).scan_file(b"payload")
    assert result.safety_score.coverage is None
    assert result.safety_score.coverage_note is None
