"""Middleware rejects whatever Surface recommends blocking by default."""
import inspect
from types import SimpleNamespace

from surface.middleware import ScanMiddleware, _rejected, scan_request


def _score(level, action):
    return SimpleNamespace(threat_level=level, recommended_action=action)


def test_default_reject_is_block():
    assert inspect.signature(scan_request).parameters["reject"].default == ("Block",)
    assert inspect.signature(ScanMiddleware.__init__).parameters["reject"].default == ("Block",)


def test_block_default_covers_risky_and_malicious_but_not_review():
    levels = {"block"}
    assert _rejected(_score("Malicious", "Block"), levels)
    assert _rejected(_score("Risky", "Block"), levels)  # an agent action Surface says to block
    assert not _rejected(_score("Suspicious", "Review"), levels)
    assert not _rejected(_score("Clean", "Allow"), levels)
