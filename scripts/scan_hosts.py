"""Batch TLS scan of a host list -> merged ScanResult JSON.

Produces real CBOM training data for the GNN planner, RL agent, and anomaly
detector by scanning public TLS endpoints (port 443) with the standard
qtrust-inspector scanner.

Usage:
    python scripts/scan_hosts.py --hosts /tmp/hosts.txt -o /tmp/top500_cbom.json
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "inspector"))

from qtrust_inspector.models import ScanResult
from qtrust_inspector.scanner import scan_host


def load_hosts(path: Path) -> list[str]:
    hosts = []
    for line in path.read_text().splitlines():
        entry = line.split(",")[-1].strip() if "," in line else line.strip()
        if entry and not entry.startswith("#"):
            hosts.append(entry)
    seen, unique = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def scan_one(host: str, ports: list[int]) -> tuple[str, ScanResult | None, str | None]:
    try:
        return host, scan_host(host, ports), None
    except Exception as e:
        return host, None, f"{type(e).__name__}: {e}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Batch TLS scan for real CBOM data")
    parser.add_argument("--hosts", required=True, help="File with one host per line")
    parser.add_argument("--ports", default="443", help="Comma-separated ports (default 443)")
    parser.add_argument("--output", "-o", required=True, help="Output JSON path")
    parser.add_argument("--workers", type=int, default=32, help="Concurrent scans")
    args = parser.parse_args()

    # Bound any socket that ignores the scanner's own timeout.
    socket.setdefaulttimeout(15)

    hosts = load_hosts(Path(args.hosts))
    ports = [int(p.strip()) for p in args.ports.split(",")]
    print(f"Scanning {len(hosts)} hosts on ports {ports} with {args.workers} workers...")

    results: list[ScanResult] = []
    failures: dict[str, str] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(scan_one, h, ports): h for h in hosts}
        for future in as_completed(futures):
            host, result, error = future.result()
            done += 1
            if error:
                failures[host] = error
            elif result is not None:
                results.append(result)
            if done % 50 == 0 or done == len(hosts):
                print(f"  [{done}/{len(hosts)}] ok={len(results)} failed={len(failures)}")

    merged = ScanResult(target=f"batch:{Path(args.hosts).name}", findings=[])
    for r in sorted(results, key=lambda r: r.target):
        merged.findings.extend(r.findings)

    out = Path(args.output)
    out.write_text(merged.model_dump_json(indent=2))

    by_alg: dict[str, int] = {}
    for f in merged.findings:
        key = f.algorithm or "unknown"
        by_alg[key] = by_alg.get(key, 0) + 1

    summary = {
        "hosts_requested": len(hosts),
        "hosts_scanned": len(results),
        "hosts_failed": len(failures),
        "total_findings": len(merged.findings),
        "by_algorithm": by_alg,
        "output": str(out),
    }
    out.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
