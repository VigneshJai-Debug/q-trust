"""qtrust_inspector -- discovers cryptographic assets and produces CBOMs."""
from .ast_scanner import (
    DETECTOR_CAPABILITIES,
    merge_findings_dedupe,
    scan_file_ast,
    scan_source_directory_ast,
    scan_with_ast,
)
from .compliance import ComplianceEngine, ComplianceFramework, ComplianceReport, ComplianceResult, ComplianceRule
from .cyclonedx import generate_cyclonedx, save_cyclonedx
from .evidence import EvidenceLedger, EvidenceEntry, CBOMDiff, compute_cbom_diff
from .file_scanner import scan_pem_files, scan_ssh_directory
from .manifest_scanner import scan_manifest
from .models import AssetFinding, ScanResult
from .pcap_scanner import analyze_pcap, analyze_zeek_ssl_log, analyze_suricata_eve, detect_capture_format
from .binary_scanner import scan_binary, scan_binaries_in_directory
from .risk_engine import RiskScore, QuantumVulnerability, calculate_risk_score
from .roadmap import CostEstimate, MigrationPhase, generate_roadmap
from .sarif import generate_sarif, save_sarif
from .conformance import run_conformance_tests
from .k8s_policy import generate_gatekeeper_policies, generate_kyverno_policies
from .remediation import REMEDIATION_DB
from .scanner import CryptoScanner, scan_directory, scan_host, scan_network, trust_findings_to_dict
from .tls_probe import probe_tls_endpoint
from .source_scanner import scan_source_directory, scan_source_file

__version__ = "1.1.0"
__all__ = [
    "AssetFinding",
    "CBOMDiff",
    "ComplianceEngine",
    "ComplianceFramework",
    "ComplianceReport",
    "ComplianceResult",
    "ComplianceRule",
    "CostEstimate",
    "CryptoScanner",
    "DETECTOR_CAPABILITIES",
    "EvidenceEntry",
    "EvidenceLedger",
    "MigrationPhase",
    "QuantumVulnerability",
    "RiskScore",
    "ScanResult",
    "calculate_risk_score",
    "compute_cbom_diff",
    "generate_cyclonedx",
    "generate_roadmap",
    "generate_sarif",
    "merge_findings_dedupe",
    "save_cyclonedx",
    "save_sarif",
    "scan_directory",
    "scan_file_ast",
    "scan_host",
    "scan_manifest",
    "scan_network",
    "scan_pem_files",
    "scan_source_directory",
    "scan_source_directory_ast",
    "scan_source_file",
    "scan_ssh_directory",
    "trust_findings_to_dict",
    "run_conformance_tests",
    "generate_kyverno_policies",
    "generate_gatekeeper_policies",
    "probe_tls_endpoint",
    "REMEDIATION_DB",
    "scan_with_ast",
    "analyze_pcap",
    "analyze_zeek_ssl_log",
    "analyze_suricata_eve",
    "detect_capture_format",
    "scan_binary",
    "scan_binaries_in_directory",
]
