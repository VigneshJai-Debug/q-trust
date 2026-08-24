"""Tests for the parallel enterprise scanner.

Uses a mocked CryptoScanner.scan_host so no network access is required.
Verifies concurrency limits, aggregation statistics, and batch risk scoring
(heuristic fallback when no GNN model is loaded).
"""
import asyncio
from typing import Any

import pytest

import qtrust_inspector.parallel_scanner as ps
from qtrust_inspector.parallel_scanner import ParallelScanner


def _fake_findings(host: str, n_assets: int = 2) -> dict[str, Any]:
    return {
        "host": host,
        "scan_timestamp": "2026-01-01T00:00:00+00:00",
        "tls_findings": [
            {
                "host": host,
                "port": 443,
                "algorithm": "RSA-2048" if i == 0 else "ML-KEM-768",
                "key_size": 2048 if i == 0 else 3168,
                "criticality": "high" if i == 0 else "low",
            }
            for i in range(n_assets)
        ],
        "ssh_findings": [],
    }


@pytest.fixture()
def scanner(monkeypatch: pytest.MonkeyPatch) -> ParallelScanner:
    monkeypatch.setattr(
        ps.CryptoScanner, "scan_host", lambda self, host: _fake_findings(host), raising=True
    )
    # Avoid SSRF guard interfering with synthetic hostnames.
    monkeypatch.setattr(ps, "validate_scan_target", lambda target: None, raising=True)
    return ParallelScanner(max_concurrent=8, timeout=5.0, use_gpu=False)


def test_parallel_scan_aggregates(scanner: ParallelScanner) -> None:
    hosts = [f"host-{i}.example.test" for i in range(25)]
    result = asyncio.run(scanner.scan_enterprise(hosts))

    stats = result["stats"]
    assert stats["total_hosts"] == 25
    assert stats["hosts_scanned"] == 25
    assert stats["hosts_failed"] == 0
    assert stats["total_assets"] == 50  # 2 TLS findings per host
    assert stats["by_algorithm"]["RSA-2048"] == 25
    assert stats["by_algorithm"]["ML-KEM-768"] == 25
    assert len(result["assets"]) == 50
    assert len(result["risk_scores"]) == 50
    assert all(0.0 <= s <= 1.0 for s in result["risk_scores"])
    assert result["gpu_used"] is False


def test_parallel_scan_respects_concurrency(scanner: ParallelScanner) -> None:
    """Peak in-flight scans must never exceed max_concurrent."""
    in_flight = 0
    peak = 0

    def slow_scan(self, host: str) -> dict[str, Any]:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            return _fake_findings(host)
        finally:
            in_flight -= 1

    ps.CryptoScanner.scan_host = slow_scan  # already monkeypatched fixture; re-wrap
    hosts = [f"h{i}.example.test" for i in range(40)]
    result = asyncio.run(scanner.scan_enterprise(hosts))
    assert peak <= scanner.max_concurrent
    assert result["stats"]["hosts_scanned"] == 40


def test_failed_hosts_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(self, host: str) -> dict[str, Any]:
        raise ConnectionError(f"unreachable: {host}")

    monkeypatch.setattr(ps.CryptoScanner, "scan_host", boom, raising=True)
    monkeypatch.setattr(ps, "validate_scan_target", lambda target: None, raising=True)

    scanner = ParallelScanner(max_concurrent=4, use_gpu=False)
    result = asyncio.run(scanner.scan_enterprise(["down1.example.test", "down2.example.test"]))
    assert result["stats"]["hosts_failed"] == 2
    assert result["stats"]["hosts_scanned"] == 0
    assert result["assets"] == []


def test_heuristic_risk_ordering(scanner: ParallelScanner) -> None:
    weak = scanner._heuristic_risk({"algorithm": "RSA-1024", "key_size": 1024})
    pqc = scanner._heuristic_risk({"algorithm": "ML-KEM-1024", "key_size": 1024})
    strong = scanner._heuristic_risk({"algorithm": "RSA-4096", "key_size": 4096})
    assert weak > strong > pqc


def test_empty_host_list(scanner: ParallelScanner) -> None:
    result = asyncio.run(scanner.scan_enterprise([]))
    assert result["stats"]["total_hosts"] == 0
    assert result["risk_scores"] == []
