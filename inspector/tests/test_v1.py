"""Comprehensive tests for qtrust_inspector v1 modules."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from qtrust_inspector import AssetFinding, CryptoScanner, ScanResult
from qtrust_inspector.compliance import ComplianceEngine, ComplianceFramework
from qtrust_inspector.evidence import EvidenceLedger, compute_cbom_diff
from qtrust_inspector.risk_engine import RiskScore, QuantumVulnerability, calculate_risk_score
from qtrust_inspector.cyclonedx import generate_cyclonedx
from qtrust_inspector.sarif import generate_sarif
from qtrust_inspector.roadmap import generate_roadmap
from qtrust_inspector.source_scanner import scan_source_file, scan_source_directory
from qtrust_inspector.manifest_scanner import scan_manifest


# ---------------------------------------------------------------------------
# 1. AssetFinding and ScanResult basics
# ---------------------------------------------------------------------------

class TestAssetFinding:
    def test_location_with_port(self):
        f = AssetFinding(asset_type="tls_certificate", host="example.com", port=443)
        assert f.location == "example.com:443"

    def test_location_without_port(self):
        f = AssetFinding(asset_type="file_key", host="/tmp/key.pem")
        assert f.location == "/tmp/key.pem"

    def test_defaults(self):
        f = AssetFinding(asset_type="x", host="y")
        assert f.criticality == "medium"
        assert f.metadata == {}
        assert f.expired is None

    def test_model_dump_roundtrip(self):
        f = AssetFinding(
            asset_type="tls_certificate",
            host="a.com",
            port=443,
            algorithm="RSA-2048",
            key_size=2048,
            criticality="high",
        )
        d = f.model_dump()
        f2 = AssetFinding(**d)
        assert f2.location == "a.com:443"
        assert f2.key_size == 2048


class TestScanResult:
    def _make_result(self):
        return ScanResult(
            target="example.com",
            findings=[
                AssetFinding(asset_type="tls_certificate", host="a.com", port=443, algorithm="RSA-2048"),
                AssetFinding(asset_type="tls_certificate", host="b.com", port=443, algorithm="ECC-P256"),
                AssetFinding(asset_type="ssh_host_key", host="c.com", port=22, algorithm="ssh-ed25519"),
            ],
        )

    def test_finding_count(self):
        r = self._make_result()
        assert r.finding_count == 3

    def test_by_algorithm(self):
        r = self._make_result()
        assert r.by_algorithm == {"RSA-2048": 1, "ECC-P256": 1, "ssh-ed25519": 1}

    def test_by_type(self):
        r = self._make_result()
        assert r.by_type == {"tls_certificate": 2, "ssh_host_key": 1}

    def test_by_algorithm_unknown(self):
        r = ScanResult(
            target="x",
            findings=[AssetFinding(asset_type="file_key", host="k", algorithm=None)],
        )
        assert r.by_algorithm == {"unknown": 1}

    def test_to_cbom_structure(self):
        r = self._make_result()
        cbom = r.to_cbom()
        assert cbom["schema_version"] == "qtrust.cbom.v1"
        assert cbom["target"] == "example.com"
        assert cbom["asset_count"] == 3
        assert len(cbom["assets"]) == 3
        assert cbom["assets"][0]["algorithm"] == "RSA-2048"

    def test_to_cbom_json_serializable(self):
        r = self._make_result()
        serialized = json.dumps(r.to_cbom())
        assert "RSA-2048" in serialized

    def test_empty_findings(self):
        r = ScanResult(target="empty.com")
        assert r.finding_count == 0
        assert r.by_algorithm == {}
        assert r.by_type == {}
        assert r.to_cbom()["asset_count"] == 0


# ---------------------------------------------------------------------------
# 2. Risk engine
# ---------------------------------------------------------------------------

class TestRiskEngine:
    def _finding(self, algorithm: str, key_type: str = "RSA", key_size: int = 2048, criticality: str = "medium"):
        return AssetFinding(
            asset_type="tls_certificate",
            host="test.com",
            port=443,
            algorithm=algorithm,
            key_type=key_type,
            key_size=key_size,
            criticality=criticality,
        )

    def test_broken_algorithm_high_risk(self):
        score = calculate_risk_score(self._finding("RSA-1024", key_size=1024))
        assert isinstance(score, RiskScore)
        assert score.value > 0.7

    def test_weakened_symmetric_medium_risk(self):
        # AES-128 is weakened by Grover's algorithm -> medium quantum risk.
        score = calculate_risk_score(self._finding("AES-128", key_type="AES", key_size=128))
        assert 0.3 < score.value <= 0.7
        assert score.quantum_vulnerability == QuantumVulnerability.WEAKENED

    def test_rsa_4096_quantum_broken_high_risk(self):
        # Shor's algorithm breaks RSA at ANY key size -- RSA-4096 must never be
        # downgraded toward safe by classical key-size logic.
        score = calculate_risk_score(self._finding("RSA-4096", key_size=4096))
        assert score.value > 0.7
        assert score.quantum_vulnerability == QuantumVulnerability.BROKEN

    def test_pqc_ready_algorithm_very_low_risk(self):
        score = calculate_risk_score(self._finding("ML-KEM-1024", key_type="ML-KEM", key_size=1024))
        assert score.value < 0.1
        assert score.quantum_vulnerability == QuantumVulnerability.PQC_READY

    def test_broken_ecdsa(self):
        score = calculate_risk_score(self._finding("ECDSA-SHA256", key_type="EC", key_size=192))
        assert score.value > 0.7

    def test_ecdsa_p384_quantum_broken_high_risk(self):
        # P-384 curve size does not protect ECDSA from Shor's algorithm.
        score = calculate_risk_score(self._finding("ECDSA-SHA384", key_type="EC", key_size=384))
        assert score.value > 0.7
        assert score.quantum_vulnerability == QuantumVulnerability.BROKEN

    def test_aes_256_stays_low_risk(self):
        # Symmetric sizing still applies: AES-256 resists Grover's algorithm.
        score = calculate_risk_score(self._finding("AES-256", key_type="AES", key_size=256))
        assert score.value < 0.3
        assert score.quantum_vulnerability == QuantumVulnerability.SAFE

    def test_risk_score_has_components(self):
        score = calculate_risk_score(self._finding("RSA-2048", key_size=2048))
        assert hasattr(score, "value")
        assert hasattr(score, "quantum_vulnerability")
        assert 0.0 <= score.value <= 1.0

    def test_quantum_vulnerability_enum(self):
        broken = calculate_risk_score(self._finding("RSA-1024", key_size=1024))
        safe = calculate_risk_score(self._finding("ML-KEM-768", key_type="ML-KEM", key_size=768))
        assert broken.quantum_vulnerability in (QuantumVulnerability.BROKEN, QuantumVulnerability.WEAKENED)
        assert safe.quantum_vulnerability == QuantumVulnerability.PQC_READY


# ---------------------------------------------------------------------------
# 3. Compliance engine
# ---------------------------------------------------------------------------

class TestComplianceEngine:
    def test_nist_sp_800_131a_rsa_2048_noncompliant(self):
        engine = ComplianceEngine(frameworks=[ComplianceFramework.NIST_SP_800_131A])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            algorithm="RSA-2048", key_type="RSA", key_size=2048,
        )
        report = engine.check(finding)
        assert report.is_compliant is False
        assert any("RSA" in v for v in report.violations)

    def test_nist_sp_800_131a_rsa_3072_compliant(self):
        engine = ComplianceEngine(frameworks=[ComplianceFramework.NIST_SP_800_131A])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            algorithm="RSA-3072", key_type="RSA", key_size=3072,
        )
        report = engine.check(finding)
        assert report.is_compliant is True

    def test_cnsa_2_0_rsa_noncompliant(self):
        engine = ComplianceEngine(frameworks=[ComplianceFramework.CNSA_2_0])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            algorithm="RSA-4096", key_type="RSA", key_size=4096,
        )
        report = engine.check(finding)
        assert report.is_compliant is False

    def test_cnsa_2_0_ml_kem_compliant(self):
        engine = ComplianceEngine(frameworks=[ComplianceFramework.CNSA_2_0])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            algorithm="ML-KEM-1024", key_type="ML-KEM", key_size=1024,
        )
        report = engine.check(finding)
        assert report.is_compliant is True

    def test_multiple_frameworks(self):
        engine = ComplianceEngine(frameworks=[
            ComplianceFramework.NIST_SP_800_131A,
            ComplianceFramework.CNSA_2_0,
        ])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            algorithm="RSA-2048", key_type="RSA", key_size=2048,
        )
        report = engine.check(finding)
        assert report.is_compliant is False
        assert len(report.violations) >= 1

    def test_compliance_framework_enum(self):
        assert hasattr(ComplianceFramework, "NIST_SP_800_131A")
        assert hasattr(ComplianceFramework, "CNSA_2_0")

    def test_report_has_framework_field(self):
        engine = ComplianceEngine(frameworks=[ComplianceFramework.NIST_SP_800_131A])
        finding = AssetFinding(
            asset_type="tls_certificate", host="t.com", port=443,
            key_type="RSA", key_size=2048,
        )
        report = engine.check(finding)
        assert hasattr(report, "framework")
        assert report.framework == ComplianceFramework.NIST_SP_800_131A


# ---------------------------------------------------------------------------
# 4. Evidence ledger
# ---------------------------------------------------------------------------

class TestEvidenceLedger:
    def test_append_and_verify(self):
        ledger = EvidenceLedger()
        cbom = {"schema_version": "qtrust.cbom.v1", "assets": []}
        entry = ledger.append(cbom)
        assert entry.index == 0
        assert ledger.verify_chain() is True

    def test_tamper_detection(self):
        ledger = EvidenceLedger()
        ledger.append({"schema_version": "qtrust.cbom.v1", "assets": []})
        ledger.append({"schema_version": "qtrust.cbom.v1", "assets": [{"x": 1}]})
        assert ledger.verify_chain() is True
        # Tamper with entry 0
        ledger.entries[0].cbom_hash = "0xtampered"
        assert ledger.verify_chain() is False

    def test_save_and_load(self):
        ledger = EvidenceLedger()
        ledger.append({"schema_version": "qtrust.cbom.v1", "assets": [{"a": 1}]})
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        ledger.save(path)
        loaded = EvidenceLedger.load(path)
        assert loaded.verify_chain() is True
        assert len(loaded.entries) == 1

    def test_compute_cbom_diff_no_change(self):
        a = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}]}
        b = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}]}
        diff = compute_cbom_diff(a, b)
        assert diff.added == []
        assert diff.removed == []
        assert diff.modified == []

    def test_compute_cbom_diff_additions(self):
        a = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}]}
        b = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}, {"id": 2}]}
        diff = compute_cbom_diff(a, b)
        assert len(diff.added) == 1
        assert diff.added[0]["id"] == 2

    def test_compute_cbom_diff_removals(self):
        a = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}, {"id": 2}]}
        b = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1}]}
        diff = compute_cbom_diff(a, b)
        assert len(diff.removed) == 1
        assert diff.removed[0]["id"] == 2

    def test_compute_cbom_diff_modifications(self):
        a = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1, "criticality": "low"}]}
        b = {"schema_version": "qtrust.cbom.v1", "assets": [{"id": 1, "criticality": "high"}]}
        diff = compute_cbom_diff(a, b)
        assert len(diff.modified) == 1


# ---------------------------------------------------------------------------
# 5. CycloneDX generation
# ---------------------------------------------------------------------------

class TestCycloneDX:
    def _make_scan_result(self):
        return ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                    fingerprint_sha256="abc123",
                ),
            ],
        )

    def test_valid_structure(self):
        result = self._make_scan_result()
        cdx = generate_cyclonedx(result)
        assert "bomFormat" in cdx
        assert cdx["bomFormat"] == "CycloneDX"
        assert "components" in cdx
        assert "version" in cdx

    def test_quantum_safe_field(self):
        result = self._make_scan_result()
        cdx = generate_cyclonedx(result)
        components = cdx.get("components", [])
        assert len(components) == 1
        comp = components[0]
        assert "quantumSafe" in comp
        assert isinstance(comp["quantumSafe"], bool)

    def test_pqc_component_is_quantum_safe(self):
        result = ScanResult(
            target="test.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="test.com", port=443,
                    algorithm="ML-KEM-1024", key_type="ML-KEM", key_size=1024,
                ),
            ],
        )
        cdx = generate_cyclonedx(result)
        assert cdx["components"][0]["quantumSafe"] is True

    def test_rsa_component_not_quantum_safe(self):
        result = self._make_scan_result()
        cdx = generate_cyclonedx(result)
        assert cdx["components"][0]["quantumSafe"] is False

    def test_empty_findings(self):
        result = ScanResult(target="empty.com")
        cdx = generate_cyclonedx(result)
        assert cdx["components"] == []
        assert cdx["metadata"]["componentCount"] == 0

    def test_cyclonedx_json_serializable(self):
        result = self._make_scan_result()
        cdx = generate_cyclonedx(result)
        serialized = json.dumps(cdx)
        assert "CycloneDX" in serialized

    def test_metadata_has_timestamp(self):
        result = self._make_scan_result()
        cdx = generate_cyclonedx(result)
        assert "metadata" in cdx
        assert "timestamp" in cdx["metadata"]


# ---------------------------------------------------------------------------
# 6. SARIF generation
# ---------------------------------------------------------------------------

class TestSarif:
    def _make_scan_result(self):
        return ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="ML-KEM-768", key_type="ML-KEM", key_size=768,
                ),
            ],
        )

    def test_valid_sarif_structure(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_rule_definitions_present(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        run = sarif["runs"][0]
        assert "tool" in run
        assert "rules" in run["tool"]["driver"]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        rule_ids = {r["id"] for r in rules}
        assert any("QUANTUM" in rid or "CRYPTO" in rid or "WEAK" in rid for rid in rule_ids)

    def test_results_match_findings(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        run = sarif["runs"][0]
        assert "results" in run
        assert len(run["results"]) == 2

    def test_sarif_result_has_level(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert "level" in r
            assert r["level"] in ("error", "warning", "note")

    def test_sarif_result_has_rule_id(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        for r in sarif["runs"][0]["results"]:
            assert "ruleId" in r

    def test_empty_findings(self):
        result = ScanResult(target="empty.com")
        sarif = generate_sarif(result)
        assert sarif["runs"][0]["results"] == []

    def test_sarif_json_serializable(self):
        result = self._make_scan_result()
        sarif = generate_sarif(result)
        serialized = json.dumps(sarif)
        assert "2.1.0" in serialized


# ---------------------------------------------------------------------------
# 7. Roadmap generation
# ---------------------------------------------------------------------------

class TestRoadmap:
    def test_generates_phases(self):
        result = ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
            ],
        )
        roadmap = generate_roadmap(result)
        assert "phases" in roadmap
        assert len(roadmap["phases"]) >= 1

    def test_cost_estimation_present(self):
        result = ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
            ],
        )
        roadmap = generate_roadmap(result)
        assert "estimated_cost" in roadmap
        assert isinstance(roadmap["estimated_cost"], (int, float))
        assert roadmap["estimated_cost"] > 0

    def test_phases_have_names(self):
        result = ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
            ],
        )
        roadmap = generate_roadmap(result)
        for phase in roadmap["phases"]:
            assert "name" in phase
            assert "tasks" in phase

    def test_roadmap_json_serializable(self):
        result = ScanResult(
            target="example.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="example.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
            ],
        )
        roadmap = generate_roadmap(result)
        serialized = json.dumps(roadmap)
        assert "phases" in serialized

    def test_empty_findings_minimal_roadmap(self):
        result = ScanResult(target="empty.com")
        roadmap = generate_roadmap(result)
        assert "phases" in roadmap
        assert "estimated_cost" in roadmap

    def test_pqc_ready_items_generate_lower_cost(self):
        classic = ScanResult(
            target="c.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="c.com", port=443,
                    algorithm="RSA-2048", key_type="RSA", key_size=2048,
                ),
            ],
        )
        pqc = ScanResult(
            target="p.com",
            findings=[
                AssetFinding(
                    asset_type="tls_certificate", host="p.com", port=443,
                    algorithm="ML-KEM-1024", key_type="ML-KEM", key_size=1024,
                ),
            ],
        )
        roadmap_classic = generate_roadmap(classic)
        roadmap_pqc = generate_roadmap(pqc)
        assert roadmap_pqc["estimated_cost"] <= roadmap_classic["estimated_cost"]


# ---------------------------------------------------------------------------
# 8. Source scanner
# ---------------------------------------------------------------------------

class TestSourceScanner:
    def test_find_crypto_in_python(self):
        code = """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
h = hashlib.sha256(b"hello")
"""
        findings = scan_source_file(code, language="python")
        assert len(findings) >= 1
        algos = {f.algorithm for f in findings}
        assert any("RSA" in a or "SHA" in a or "hash" in a.lower() for a in algos)

    def test_find_crypto_in_javascript(self):
        code = """
const crypto = require('crypto');
const key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const hash = crypto.createHash('sha256');
"""
        findings = scan_source_file(code, language="javascript")
        assert len(findings) >= 1

    def test_no_crypto_in_plain_text(self):
        code = "print('hello world')"
        findings = scan_source_file(code, language="python")
        assert len(findings) == 0

    def test_scan_source_directory(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "crypto_util.py").write_text(
            "from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        )
        (src / "plain.py").write_text("x = 1\n")
        findings = scan_source_directory(str(src))
        assert len(findings) >= 1

    def test_finding_has_host_as_file_path(self):
        code = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        findings = scan_source_file(code, language="python")
        assert len(findings) >= 1
        assert findings[0].asset_type == "source_crypto_usage"


# ---------------------------------------------------------------------------
# 9. Manifest scanner
# ---------------------------------------------------------------------------

class TestManifestScanner:
    def test_find_crypto_deps_package_json(self):
        manifest = {
            "name": "test-app",
            "dependencies": {
                "crypto-js": "^4.1.1",
                "express": "^4.18.0",
                "node-forge": "^1.3.0",
            }
        }
        findings = scan_manifest(manifest, manifest_type="package.json")
        assert len(findings) >= 1
        dep_names = {f.metadata.get("package_name", f.host) for f in findings}
        assert any("crypto" in d.lower() or "forge" in d.lower() for d in dep_names)

    def test_find_crypto_deps_requirements_txt(self):
        manifest = "cryptography==41.0.0\nrequests==2.31.0\npycryptodome==3.19.0\n"
        findings = scan_manifest(manifest, manifest_type="requirements.txt")
        assert len(findings) >= 1
        dep_names = {f.metadata.get("package_name", f.host) for f in findings}
        assert any("crypto" in d.lower() for d in dep_names)

    def test_no_crypto_deps(self):
        manifest = {
            "name": "safe-app",
            "dependencies": {
                "lodash": "^4.17.0",
                "express": "^4.18.0",
            }
        }
        findings = scan_manifest(manifest, manifest_type="package.json")
        assert len(findings) == 0

    def test_findings_have_asset_type(self):
        manifest = {"dependencies": {"cryptography": "41.0.0"}}
        findings = scan_manifest(manifest, manifest_type="package.json")
        assert len(findings) >= 1
        assert findings[0].asset_type == "dependency_crypto_library"

    def test_requirements_txt_with_pyproject(self):
        manifest = "[project]\ndependencies = [\n  'cryptography>=3.0',\n  'requests>=2.0',\n]\n"
        findings = scan_manifest(manifest, manifest_type="requirements.txt")
        assert len(findings) >= 1


# ---------------------------------------------------------------------------
# 10. PCAP scanner
# ---------------------------------------------------------------------------

class TestPCAPScanner:
    def test_analyze_pcap_nonexistent_file(self):
        from qtrust_inspector.pcap_scanner import analyze_pcap
        result = analyze_pcap("/nonexistent/file.pcap")
        assert "error" in result or result.get("flows") == []

    def test_analyze_pcap_structure(self):
        from qtrust_inspector.pcap_scanner import analyze_pcap
        result = analyze_pcap("/nonexistent/file.pcap")
        assert "flows" in result
        assert isinstance(result["flows"], list)

    def test_analyze_pcap_returns_dict(self):
        from qtrust_inspector.pcap_scanner import analyze_pcap
        result = analyze_pcap("/nonexistent/file.pcap")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# 11. Remediation module
# ---------------------------------------------------------------------------

class TestRemediation:
    def test_remediation_db_has_languages(self):
        from qtrust_inspector.remediation import REMEDIATION_DB
        assert "python" in REMEDIATION_DB
        assert "javascript" in REMEDIATION_DB
        assert "go" in REMEDIATION_DB
        assert "rust" in REMEDIATION_DB

    def test_remediation_has_required_fields(self):
        from qtrust_inspector.remediation import REMEDIATION_DB
        for lang, algos in REMEDIATION_DB.items():
            for algo_key, remed in algos.items():
                assert "pattern" in remed, f"{lang}/{algo_key} missing 'pattern'"
                assert "replacement" in remed, f"{lang}/{algo_key} missing 'replacement'"
                assert "explanation" in remed, f"{lang}/{algo_key} missing 'explanation'"
                assert "nist" in remed, f"{lang}/{algo_key} missing 'nist'"

    def test_remediation_covers_key_algorithms(self):
        from qtrust_inspector.remediation import REMEDIATION_DB
        assert "RSA" in REMEDIATION_DB["python"]
        assert "ECDSA" in REMEDIATION_DB["python"]

    def test_remediation_has_all_languages(self):
        from qtrust_inspector.remediation import REMEDIATION_DB
        expected = {"python", "javascript", "go", "java", "rust", "c", "csharp", "php", "swift", "ruby", "kotlin"}
        assert expected.issubset(set(REMEDIATION_DB.keys()))


# ---------------------------------------------------------------------------
# 12. Conformance testing
# ---------------------------------------------------------------------------

class TestConformance:
    def test_ml_kem_768_parameter_sizes(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("ML-KEM-768")
        assert result.algorithm.value == "ML-KEM-768"
        assert result.level == 768
        assert result.total_tests > 0
        # Deterministic spec-table checks actually run and pass.
        assert result.failed == 0
        assert result.passed > 0
        assert result.conformance_score == 100.0
        assert result.parameter_set_valid is True

    def test_ml_kem_768_executes_not_all_skip(self):
        from qtrust_inspector.conformance import TestStatus, run_conformance_tests
        result = run_conformance_tests("ML-KEM-768")
        statuses = {t.status for t in result.tests}
        assert statuses & {TestStatus.PASS}, "spec-table checks should execute and PASS"
        assert TestStatus.FAIL not in statuses
        # Skips are only for genuinely external validations (KATs/ACVP).
        skipped = [t for t in result.tests if t.status == TestStatus.SKIP]
        assert skipped, "keygen/encaps KATs should be reported as SKIP"
        assert all(
            "requires NIST ACVP vectors / liboqs integration" in t.details for t in skipped
        )
        assert all(t.name.endswith("_kat") or t.name.endswith("_vectors") for t in skipped)

    def test_ml_kem_768_spec_values(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("ML-KEM-768")
        by_name = {t.name: t for t in result.tests}
        assert by_name["ML-KEM-768_pk_size"].status.value == "PASS"
        assert by_name["ML-KEM-768_pk_size"].expected == "1184"
        assert by_name["ML-KEM-768_sk_size"].expected == "2400"
        assert by_name["ML-KEM-768_ct_size"].expected == "1088"

    def test_ml_dsa_65_parameter_sizes(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("ML-DSA-65")
        assert result.algorithm.value == "ML-DSA-65"
        assert result.level == 65
        assert result.total_tests > 0
        assert result.failed == 0
        assert result.passed > 0
        assert result.conformance_score == 100.0

    def test_slh_dsa_128s(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("SLH-DSA-128s")
        assert result.algorithm.value == "SLH-DSA-128s"
        assert result.total_tests > 0
        assert result.failed == 0
        assert result.passed > 0
        assert result.conformance_score == 100.0

    def test_all_variants_validate_clean(self):
        from qtrust_inspector.conformance import run_conformance_tests
        for algo in (
            "ML-KEM-512", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-87",
            "SLH-DSA-128f", "SLH-DSA-192s", "SLH-DSA-192f",
            "SLH-DSA-256s", "SLH-DSA-256f",
        ):
            r = run_conformance_tests(algo)
            assert r.failed == 0, f"{algo}: {[t.name for t in r.tests if t.status.value == 'FAIL']}"
            assert r.parameter_set_valid is True

    def test_mismatch_injection_surfaces_fail(self, monkeypatch):
        from qtrust_inspector import conformance
        monkeypatch.setitem(conformance.ML_KEM_PARAMS["ML-KEM-768"], "ct_size", 9999)
        result = conformance.run_conformance_tests("ML-KEM-768")
        failures = [t for t in result.tests if t.status.value == "FAIL"]
        assert len(failures) >= 1
        assert any(t.name == "ML-KEM-768_ct_size" for t in failures)
        bad = next(t for t in failures if t.name == "ML-KEM-768_ct_size")
        assert bad.expected == "1088"
        assert bad.actual == "9999"
        assert result.failed >= 1
        assert result.conformance_score < 100.0
        assert result.parameter_set_valid is False
        assert not result.fips_compliant

    def test_conformance_result_to_dict(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("ML-KEM-512")
        d = result.to_dict()
        assert "algorithm" in d
        assert "tests" in d
        assert isinstance(d["tests"], list)
        assert "conformance_score" in d
        assert "parameter_set_valid" in d
        # Backward-compat alias still present.
        assert "fips_compliant" in d
        assert d["fips_compliant"] == d["parameter_set_valid"]

    def test_ml_kem_512_vs_1024_different_levels(self):
        from qtrust_inspector.conformance import run_conformance_tests
        r512 = run_conformance_tests("ML-KEM", "512")
        r1024 = run_conformance_tests("ML-KEM", "1024")
        assert r512.level == 512
        assert r1024.level == 1024
        assert r512.algorithm != r1024.algorithm

    def test_generic_ml_kem_defaults_to_768(self):
        from qtrust_inspector.conformance import run_conformance_tests
        result = run_conformance_tests("ML-KEM")
        assert result.level == 768


# ---------------------------------------------------------------------------
# 13. K8s policy generation
# ---------------------------------------------------------------------------

class TestK8sPolicy:
    def test_kyverno_policies_generated(self):
        from qtrust_inspector.k8s_policy import generate_kyverno_policies
        policies = generate_kyverno_policies()
        assert len(policies) >= 4
        assert all(p.engine == "kyverno" for p in policies)

    def test_gatekeeper_policies_generated(self):
        from qtrust_inspector.k8s_policy import generate_gatekeeper_policies
        policies = generate_gatekeeper_policies()
        assert len(policies) >= 2
        assert all(p.engine == "gatekeeper" for p in policies)

    def test_policy_summary(self):
        from qtrust_inspector.k8s_policy import generate_all_policies, generate_policy_summary
        policies = generate_all_policies()
        summary = generate_policy_summary(policies)
        assert summary["total_policies"] >= 6
        assert "kyverno" in summary["engines"]
        assert "gatekeeper" in summary["engines"]
        assert len(summary["protected_resources"]) >= 3

    def test_format_policies_yaml(self):
        from qtrust_inspector.k8s_policy import generate_kyverno_policies, format_policies_yaml
        policies = generate_kyverno_policies()
        yaml_str = format_policies_yaml(policies, "kyverno")
        assert "apiVersion" in yaml_str
        assert "ClusterPolicy" in yaml_str

    def test_admission_webhook(self):
        from qtrust_inspector.k8s_policy import generate_admission_webhook
        webhook = generate_admission_webhook()
        assert webhook["kind"] == "ValidatingWebhookConfiguration"
        assert len(webhook["webhooks"]) == 1
        assert webhook["webhooks"][0]["name"] == "pqc.qtrust.dev"


# ---------------------------------------------------------------------------
# 14. TLS deep probe
# ---------------------------------------------------------------------------

class TestTLSProbe:
    def test_client_hello_building(self):
        from qtrust_inspector.tls_probe import _build_client_hello
        hello = _build_client_hello("example.com")
        assert isinstance(hello, bytes)
        assert len(hello) > 0
        assert hello[0] == 0x16  # TLS record

    def test_client_hello_with_pqc(self):
        from qtrust_inspector.tls_probe import _build_client_hello
        hello = _build_client_hello("example.com", include_pqc=True)
        assert isinstance(hello, bytes)
        assert len(hello) > 0

    def test_tls_group_codepoints(self):
        from qtrust_inspector.tls_probe import TLS_GROUP_CODEPOINTS
        assert 0x11EC in TLS_GROUP_CODEPOINTS  # X25519MLKEM768
        assert 0x639A in TLS_GROUP_CODEPOINTS  # MLKEM768
        assert 0x0012 in TLS_GROUP_CODEPOINTS  # x25519

    def test_tls_sigalg_codepoints(self):
        from qtrust_inspector.tls_probe import TLS_SIGALG_CODEPOINTS
        assert 0x0905 in TLS_SIGALG_CODEPOINTS  # MLDSA65
        assert 0x0807 in TLS_SIGALG_CODEPOINTS  # Ed25519

    def test_tls_probe_result_structure(self):
        from qtrust_inspector.tls_probe import probe_tls_endpoint
        import pytest
        # Reserved ranges are rejected by the scan-target guard (audit I-3).
        with pytest.raises(ValueError, match="forbidden"):
            probe_tls_endpoint("192.0.2.1", timeout=1.0)  # TEST-NET-1
        # Unresolvable hosts pass the guard but fail to connect — the probe
        # still returns a well-formed result dict.
        result = probe_tls_endpoint("qtrust-test-does-not-exist.invalid", timeout=1.0)
        assert "host" in result
        assert "risk_level" in result
        assert "pqc_kem_detected" in result
        assert "recommendations" in result
