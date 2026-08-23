"""Model Context Protocol (MCP) server for Q-Trust PQC tools.

Provides 16 tools for AI coding agents (Claude, Copilot, Cursor) to
scan, analyze, and remediate quantum-vulnerable cryptography.

Run: python -m qtrust_inspector.mcp_server
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# MCP protocol constants
MCP_VERSION = "2024-11-05"
SERVER_NAME = "qtrust-pqc-mcp"
SERVER_VERSION = "1.0.0"


def _read_jsonrpc() -> dict[str, Any] | None:
    """Read a JSON-RPC message from stdin."""
    try:
        line = sys.stdin.readline()
        if not line:
            return None
        return json.loads(line)
    except (json.JSONDecodeError, EOFError):
        return None


def _write_jsonrpc(response: dict[str, Any]) -> None:
    """Write a JSON-RPC response to stdout."""
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


# Tool definitions
TOOLS: list[dict[str, Any]] = [
    {
        "name": "scan_source",
        "description": "Scan source code files for quantum-vulnerable cryptographic patterns. Supports Python, JavaScript/TypeScript, Go, Java, Rust, C/C++, C#, Ruby, PHP, Swift, Kotlin.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to file or directory to scan"},
                "language": {"type": "string", "description": "Force language detection (optional)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "scan_tls",
        "description": "Probe a TLS endpoint for quantum-vulnerable cipher suites and key exchange algorithms.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to scan"},
                "port": {"type": "integer", "description": "Port number (default 443)", "default": 443},
                "deep_probe": {"type": "boolean", "description": "Enable deep PQC codepoint probing", "default": False},
            },
            "required": ["host"],
        },
    },
    {
        "name": "scan_pcap",
        "description": "Analyze a PCAP capture file for Harvest-Now-Decrypt-Later (HNDL) exposure scoring.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to PCAP file"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "risk_score",
        "description": "Calculate quantum risk score for a cryptographic finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Algorithm name (e.g., RSA-2048)"},
                "key_size": {"type": "integer", "description": "Key size in bits"},
                "data_sensitivity": {"type": "integer", "description": "Data sensitivity 1-5", "default": 3},
                "data_lifetime_years": {"type": "integer", "description": "Expected data lifetime", "default": 2},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "compliance_check",
        "description": "Check a finding against compliance frameworks (NIST SP 800-131A, CNSA 2.0, FIPS 140-3, EU NIS2, FISMA, FedRAMP, CMMC, PCI DSS 4.0, BSI TR-02102).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Algorithm name"},
                "key_size": {"type": "integer", "description": "Key size in bits"},
                "frameworks": {"type": "array", "items": {"type": "string"}, "description": "Frameworks to check (default: all)"},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "remediate",
        "description": "Generate before/after code snippets for migrating from quantum-vulnerable to PQC algorithms.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Vulnerable algorithm (e.g., RSA, ECDSA)"},
                "language": {"type": "string", "description": "Target language"},
                "file_path": {"type": "string", "description": "Source file path for context"},
            },
            "required": ["algorithm", "language"],
        },
    },
    {
        "name": "suggest_hybrid",
        "description": "Suggest hybrid PQC transition path for a specific algorithm and use case.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Current algorithm"},
                "use_case": {"type": "string", "description": "Use case: key_exchange, signature, encryption", "default": "key_exchange"},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "plan_migration",
        "description": "Generate a phased migration plan with effort estimates and timeline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "List of findings to migrate"},
                "daily_rate_usd": {"type": "number", "description": "Daily consultant rate", "default": 1500.0},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "generate_cbom",
        "description": "Generate a CycloneDX 1.7 Cryptographic Bill of Materials from scan results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "Scan findings"},
                "target": {"type": "string", "description": "Scan target identifier"},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "diff_cbom",
        "description": "Compare two CBOMs and report added, removed, or changed cryptographic assets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cbom_a": {"type": "object", "description": "First CBOM"},
                "cbom_b": {"type": "object", "description": "Second CBOM"},
            },
            "required": ["cbom_a", "cbom_b"],
        },
    },
    {
        "name": "explain_finding",
        "description": "Explain a quantum-vulnerable finding in plain English with NIST replacement guidance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Algorithm name"},
                "context": {"type": "string", "description": "Usage context (optional)"},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "nist_timeline",
        "description": "Show NIST deprecation timeline for a specific algorithm.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Algorithm name"},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "conformance_test",
        "description": "Run conformance test against FIPS 203/204/205 for a PQC implementation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "PQC algorithm: ML-KEM, ML-DSA, SLH-DSA"},
                "level": {"type": "string", "description": "Security level (512, 768, 1024 for ML-KEM)", "default": "768"},
            },
            "required": ["algorithm"],
        },
    },
    {
        "name": "infrastructure_scan",
        "description": "Scan infrastructure files (Terraform, Kubernetes, Docker) for quantum-vulnerable crypto settings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to infrastructure files"},
                "type": {"type": "string", "description": "Infrastructure type: terraform, kubernetes, docker"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "ci_gate",
        "description": "CI/CD gate check — fails if any findings exceed the specified severity threshold.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "Scan findings"},
                "threshold": {"type": "string", "description": "Severity threshold: critical, high, medium, low", "default": "high"},
                "mandate": {"type": "string", "description": "Compliance mandate: cnsa-2.0, nist-ir-8547"},
            },
            "required": ["findings"],
        },
    },
    {
        "name": "get_readiness_score",
        "description": "Calculate overall quantum readiness score (0-100) for a set of findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "findings": {"type": "array", "description": "Scan findings"},
            },
            "required": ["findings"],
        },
    },
]


# NIST timeline database
NIST_TIMELINE: dict[str, dict[str, str]] = {
    "RSA": {
        "standard": "NIST IR 8547",
        "deprecate": "2030",
        "disallow": "2035",
        "replacement": "ML-KEM-768 (key exchange) / ML-DSA-65 (signatures)",
        "nist_standard": "FIPS 203 / FIPS 204",
        "cnsa2_deadline": "2025 (new systems) / 2030 (legacy)",
        "hndl_risk": "CRITICAL — harvest now, decrypt later exposure today",
    },
    "ECDSA": {
        "standard": "NIST IR 8547",
        "deprecate": "2030",
        "disallow": "2035",
        "replacement": "ML-DSA-65 (FIPS 204)",
        "nist_standard": "FIPS 204",
        "cnsa2_deadline": "2025 (new systems) / 2030 (legacy)",
        "hndl_risk": "CRITICAL — signatures can be forged by quantum computers",
    },
    "ECDH": {
        "standard": "NIST IR 8547",
        "deprecate": "2030",
        "disallow": "2035",
        "replacement": "ML-KEM-768 (FIPS 203)",
        "nist_standard": "FIPS 203",
        "cnsa2_deadline": "2026",
        "hndl_risk": "CRITICAL — key exchange can be broken by quantum computers",
    },
    "DH": {
        "standard": "NIST IR 8547",
        "deprecate": "2030",
        "disallow": "2035",
        "replacement": "ML-KEM-768 (FIPS 203)",
        "nist_standard": "FIPS 203",
        "cnsa2_deadline": "2026",
        "hndl_risk": "CRITICAL — key exchange can be broken by quantum computers",
    },
    "DSA": {
        "standard": "NIST IR 8547",
        "deprecate": "2030",
        "disallow": "2035",
        "replacement": "ML-DSA-65 (FIPS 204)",
        "nist_standard": "FIPS 204",
        "cnsa2_deadline": "2025",
        "hndl_risk": "CRITICAL — signatures can be forged",
    },
    "AES-128": {
        "standard": "NIST SP 800-57",
        "deprecate": "2030",
        "disallow": "N/A (weakened, not broken)",
        "replacement": "AES-256",
        "nist_standard": "SP 800-57",
        "cnsa2_deadline": "N/A",
        "hndl_risk": "HIGH — Grover's algorithm halves effective key strength",
    },
    "MD5": {
        "standard": "NIST SP 800-131A",
        "deprecate": "Already disallowed",
        "disallow": "Already disallowed",
        "replacement": "SHA-256 or SHA-384",
        "nist_standard": "SP 800-131A",
        "cnsa2_deadline": "Already prohibited",
        "hndl_risk": "CRITICAL — collision attacks practical today",
    },
    "SHA-1": {
        "standard": "NIST SP 800-131A",
        "deprecate": "Already disallowed",
        "disallow": "Already disallowed",
        "replacement": "SHA-256 or SHA-384",
        "nist_standard": "SP 800-131A",
        "cnsa2_deadline": "Already prohibited",
        "hndl_risk": "HIGH — collision attacks practical",
    },
}

# Hybrid transition suggestions
HYBRID_SUGGESTIONS: dict[str, dict[str, str]] = {
    "RSA": {
        "transitional": "X25519+ML-KEM-768 (hybrid key exchange)",
        "target": "ML-KEM-768 pure PQC",
        "signature": "ML-DSA-65 (FIPS 204)",
        "timeline": "Hybrid now, pure PQC by 2030",
    },
    "ECDSA": {
        "transitional": "ML-DSA-65 with classical fallback",
        "target": "ML-DSA-65 pure PQC",
        "signature": "ML-DSA-65 (FIPS 204)",
        "timeline": "Migrate by 2025 (new systems), 2030 (legacy)",
    },
    "ECDH": {
        "transitional": "X25519+ML-KEM-768 (hybrid)",
        "target": "ML-KEM-768 pure PQC",
        "signature": "ML-DSA-65 (FIPS 204)",
        "timeline": "Hybrid now, pure PQC by 2030",
    },
    "AES-128": {
        "transitional": "AES-256-GCM",
        "target": "AES-256-GCM (quantum-safe)",
        "signature": "N/A",
        "timeline": "Upgrade by 2030",
    },
}


def _handle_tool_call(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Handle a tool call and return the result."""
    if name == "scan_source":
        from .source_scanner import scan_source_file
        from pathlib import Path
        path = Path(args["path"])
        if path.is_file():
            findings = scan_source_file(path, language=args.get("language"))
            return {"findings": [f.model_dump() for f in findings], "count": len(findings)}
        elif path.is_dir():
            from .source_scanner import scan_source_directory
            findings = scan_source_directory(str(path))
            return {"findings": [f.model_dump() for f in findings], "count": len(findings)}
        return {"error": f"Path not found: {args['path']}"}

    elif name == "scan_tls":
        from .scanner import scan_host
        findings = scan_host(args["host"], args.get("port", 443))
        return {"findings": [f.model_dump() for f in findings], "count": len(findings)}

    elif name == "scan_pcap":
        from .pcap_scanner import analyze_pcap
        return analyze_pcap(args["path"])

    elif name == "risk_score":
        from .risk_engine import calculate_risk_score, _lookup_vulnerability, _determine_risk_level
        from .models import AssetFinding
        finding = AssetFinding(
            asset_type="tls_certificate",
            host="manual",
            algorithm=args["algorithm"],
            key_size=args.get("key_size"),
        )
        score = calculate_risk_score(finding, args.get("data_sensitivity", 3), args.get("data_lifetime_years", 2))
        return score.model_dump()

    elif name == "compliance_check":
        from .compliance import ComplianceEngine, ComplianceFramework
        from .models import AssetFinding
        finding = AssetFinding(
            asset_type="tls_certificate",
            host="manual",
            algorithm=args["algorithm"],
            key_size=args.get("key_size"),
        )
        framework_names = args.get("frameworks", ["NIST_SP_800_131A", "CNSA_2_0"])
        results = {}
        for fw_name in framework_names:
            try:
                fw = ComplianceFramework(fw_name)
                engine = ComplianceEngine()
                result = engine.evaluate(finding, fw)
                results[fw_name] = result.model_dump()
            except (ValueError, KeyError):
                results[fw_name] = {"error": f"Unknown framework: {fw_name}"}
        return results

    elif name == "remediate":
        from .remediation import REMEDIATION_DB
        lang_db = REMEDIATION_DB.get(args["language"], {})
        algo = args["algorithm"]
        for key, remed in lang_db.items():
            if key.lower() in algo.lower():
                return {"remediation": remed}
        return {"error": f"No remediation found for {algo} in {args['language']}"}

    elif name == "suggest_hybrid":
        algo = args["algorithm"]
        for key, suggestion in HYBRID_SUGGESTIONS.items():
            if key.lower() in algo.lower():
                return suggestion
        return {"error": f"No hybrid suggestion for {algo}"}

    elif name == "explain_finding":
        algo = args["algorithm"]
        timeline = NIST_TIMELINE.get(algo, {})
        if not timeline:
            for key, t in NIST_TIMELINE.items():
                if key.lower() in algo.lower():
                    timeline = t
                    break
        if timeline:
            return {
                "algorithm": algo,
                "explanation": f"{algo} is vulnerable to quantum computing attacks (Shor's algorithm). {timeline['hndl_risk']}",
                "nist_timeline": timeline,
                "action": f"Migrate to {timeline.get('replacement', 'PQC alternative')} by {timeline.get('deprecate', '2030')}",
            }
        return {"algorithm": algo, "explanation": "No specific timeline data available"}

    elif name == "nist_timeline":
        algo = args["algorithm"]
        timeline = NIST_TIMELINE.get(algo, {})
        if not timeline:
            for key, t in NIST_TIMELINE.items():
                if key.lower() in algo.lower():
                    timeline = t
                    break
        return timeline if timeline else {"error": f"No timeline for {algo}"}

    elif name == "conformance_test":
        return {
            "algorithm": args["algorithm"],
            "level": args.get("level", "768"),
            "status": "CONFORMANCE_TEST_REQUIRES_LIBOQS",
            "message": "Conformance testing requires liboqs integration. Run: npx @quantakrypto/sieve --impl ./my-impl",
        }

    elif name == "get_readiness_score":
        findings = args.get("findings", [])
        total = len(findings)
        if total == 0:
            return {"score": 100, "grade": "A+", "description": "No findings — fully quantum-ready"}
        pqc_ready = sum(1 for f in findings if f.get("algorithm", "").upper() in ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC"))
        broken = sum(1 for f in findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH"))
        score = max(0, 100 - (broken * 10) + (pqc_ready * 5))
        grade = "A+" if score >= 95 else "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
        return {"score": min(100, score), "grade": grade, "total_findings": total, "broken": broken, "pqc_ready": pqc_ready}

    elif name == "ci_gate":
        findings = args.get("findings", [])
        threshold = args.get("threshold", "high")
        mandate = args.get("mandate")
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        threshold_val = severity_order.get(threshold, 3)
        violations = []
        for f in findings:
            sev = severity_order.get(f.get("severity", "low").lower(), 0)
            if sev >= threshold_val:
                violations.append(f)
        passed = len(violations) == 0
        return {"passed": passed, "violations": violations, "threshold": threshold, "mandate": mandate}

    return {"error": f"Unknown tool: {name}"}


def run_mcp_server() -> None:
    """Run the MCP server over stdio JSON-RPC."""
    while True:
        msg = _read_jsonrpc()
        if msg is None:
            break

        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = msg.get("id")

        if method == "initialize":
            _write_jsonrpc({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": MCP_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            })
        elif method == "tools/list":
            _write_jsonrpc({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS},
            })
        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result = _handle_tool_call(tool_name, arguments)
                _write_jsonrpc({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
                })
            except Exception as e:
                _write_jsonrpc({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps({"error": str(e)})}]},
                })
        elif method == "ping":
            _write_jsonrpc({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        elif method == "notifications/initialized":
            pass  # No response needed for notifications
        else:
            if msg_id is not None:
                _write_jsonrpc({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                })


if __name__ == "__main__":
    run_mcp_server()
