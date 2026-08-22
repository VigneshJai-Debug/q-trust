from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .file_scanner import scan_pem_files, scan_ssh_directory
from .models import AssetFinding, ScanResult

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

DEFAULT_TIMEOUT = 5
CBOM_SCHEMA_VERSION = "qtrust.cbom.v1"

# Map of algorithms to their post-quantum readiness status.
PQC_ALGORITHMS = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    "ML-DSA-441", "ML-DSA-659", "ML-DSA-877",
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "HQC-128", "HQC-192", "HQC-256",
    "FALCON-512", "FALCON-1024",
    "SPHINCS+",
}

# Criticality heuristic: shorter RSA keys and broken curves score higher.
WEAK_KEY_THRESHOLDS = {
    "RSA": 2048,   # <2048 = Critical, ==2048 = High, >2048 = Medium
    "DSA": 2048,
    "EC": 256,     # <256 = Critical
}


class CryptoScanner:
    """Scans hosts for cryptographic assets and generates a CBOM."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        """Initialize the scanner.

        Args:
            timeout: Socket connect/read timeout in seconds.
        """
        self.timeout = timeout
        self._nm = None
        if NMAP_AVAILABLE:
            try:
                self._nm = nmap.PortScanner()
            except Exception:
                self._nm = None

    # ------------------------------------------------------------------
    # TLS scanning
    # ------------------------------------------------------------------
    def scan_tls(self, host: str, port: int = 443) -> AssetFinding | None:
        """Scan a TLS endpoint and extract certificate metadata.

        Args:
            host: Hostname or IP address.
            port: TLS port (default 443).

        Returns:
            An AssetFinding object or None if failed.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
        except (TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            return None

        if not der_cert:
            return None

        cert = x509.load_der_x509_certificate(der_cert)

        try:
            issuer = cert.issuer.rfc4514_string()
        except Exception:
            issuer = str(cert.issuer)

        try:
            subject = cert.subject.rfc4514_string()
        except Exception:
            subject = str(cert.subject)

        # Public key info
        public_key = cert.public_key()
        key_type = type(public_key).__name__
        key_size = getattr(public_key, "key_size", 0)

        # Signature algorithm
        try:
            sig_algorithm = cert.signature_algorithm_oid._name
        except Exception:
            sig_algorithm = "unknown"

        # Fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

        # Validity
        try:
            not_before = cert.not_valid_before_utc.isoformat()
            not_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            not_before = cert.not_valid_before.isoformat()
            not_after = cert.not_valid_after.isoformat()

        now = datetime.now(timezone.utc)
        try:
            expired = cert.not_valid_after_utc < now
        except AttributeError:
            expired = cert.not_valid_after.replace(tzinfo=timezone.utc) < now

        return AssetFinding(
            asset_type="tls_certificate",
            host=host,
            port=port,
            algorithm=sig_algorithm,
            key_type=key_type,
            key_size=key_size,
            issuer=issuer,
            subject=subject,
            serial_number=str(cert.serial_number),
            not_before=not_before,
            not_after=not_after,
            expired=expired,
            fingerprint_sha256=fingerprint_sha256,
            cipher=cipher[0] if cipher else None,
            metadata={"issuer": issuer, "subject": subject, "serial": str(cert.serial_number)}
        )

        # ------------------------------------------------------------------
    # SSH scanning
    # ------------------------------------------------------------------
    def scan_ssh(self, host: str, port: int = 22) -> AssetFinding | None:
        """Scan an SSH endpoint and extract the server host key.

        Args:
            host: Hostname or IP address.
            port: SSH port (default 22).

        Returns:
            An AssetFinding object or None if failed.
        """
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                # Read the SSH banner
                banner = sock.recv(256).decode("utf-8", errors="replace").strip()
                if not banner.startswith("SSH-"):
                    return None

                # Send our banner
                sock.sendall(b"SSH-2.0-cryptography-inspector_0.1\r\n")

                # Read kex_init packet to discover host key algorithms
                packet = self._read_ssh_packet(sock)
                if packet is None:
                    return None

                # Parse the kex_init to find supported host key algorithms
                host_key_algos = self._extract_host_key_algos(packet)

                # Use ssh-keyscan as a fallback to get the actual key
                return self._ssh_keys_scan(host, port, host_key_algos, banner)
        except (TimeoutError, ConnectionRefusedError, OSError):
            return None

    @staticmethod
    def _read_ssh_packet(sock: socket.socket) -> bytes | None:
        """Read a single SSH packet payload from the socket."""
        try:
            # SSH binary packet format: uint32 packet_length, byte padding_length, payload
            header = sock.recv(5)
            if len(header) < 5:
                return None
            packet_length = int.from_bytes(header[:4], "big")
            padding_length = header[4]
            payload_length = packet_length - padding_length - 1
            payload = b""
            while len(payload) < payload_length:
                chunk = sock.recv(payload_length - len(payload))
                if not chunk:
                    break
                payload += chunk
            return payload
        except OSError:
            return None

    @staticmethod
    def _extract_host_key_algos(kex_payload: bytes) -> list[str]:
        """Extract the list of host key algorithms from a kex_payload."""
        if not kex_payload or len(kex_payload) < 16:
            return []
        # Skip 16 bytes cookie, then 8 name-lists (each prefixed by uint32 length)
        offset = 16
        # The 8th name-list is server_host_key_algorithms (index 7)
        for i in range(7):
            if offset + 4 > len(kex_payload):
                return []
            length = int.from_bytes(kex_payload[offset:offset + 4], "big")
            offset += 4 + length
        if offset + 4 > len(kex_payload):
            return []
        length = int.from_bytes(kex_payload[offset:offset + 4], "big")
        offset += 4
        if offset + length > len(kex_payload):
            return []
        return kex_payload[offset:offset + length].decode("ascii", errors="replace").split(",")

    @staticmethod
    def _ssh_keys_scan(
        host: str, port: int, host_key_algos: list[str], banner: str
    ) -> AssetFinding | None:
        """Use ssh-keys    _scan as a fallback to fetch the host key."""
        try:
            result = subprocess.run(
                ["ssh-keyscan", "-p", str(port), "-T", str(DEFAULT_TIMEOUT), host],
                capture_output=True,
                text=True,
                timeout=DEFAULT_TIMEOUT + 5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

        lines = [
            line for line in result.stdout.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not lines:
            return None

        # Parse the first line: host port algorithm key
        parts = lines[0].split()
        # Format can be "host algorithm key" or "host port algorithm key"
        if len(parts) >= 3 and (parts[1].isdigit() or len(parts) == 3):
            if parts[1].isdigit():
                algorithm = parts[2]
                raw_key_b64 = parts[3] if len(parts) > 3 else ""
            else:
                algorithm = parts[1]
                raw_key_b64 = parts[2] if len(parts) > 2 else ""
        else:
            return None

        # Compute key size and fingerprint
        try:
            key_bytes = base64.b64decode(raw_key_b64)
            fingerprint_sha256 = hashlib.sha256(key_bytes).hexdigest()
        except Exception:
            key_bytes = b""
            fingerprint_sha256 = ""

        key_type = algorithm
        key_size = 0
        if algorithm.startswith("ssh-rsa"):
            key_type = "RSA"
            # RSA key size is encoded in the key blob
            if len(key_bytes) >= 11:
                # ssh-rsa + e + n; n is the modulus
                try:
                    offset = 7  # length of "ssh-rsa" string
                    e_len = int.from_bytes(key_bytes[offset:offset + 4], "big")
                    offset += 4 + e_len
                    n_len = int.from_bytes(key_bytes[offset:offset + 4], "big")
                    key_size = n_len * 8
                except Exception:
                    key_size = 0
        elif algorithm.startswith("ssh-ed25519"):
            key_type = "Ed25519"
            key_size = 256
        elif algorithm.startswith("ecdsa-sha2"):
            key_type = "EC"
            if "nistp256" in algorithm:
                key_size = 256
            elif "nistp384" in algorithm:
                key_size = 384
            elif "nistp521" in algorithm:
                key_size = 521
        elif algorithm.startswith("ssh-dss"):
            key_type = "DSA"
            key_size = 1024

        return AssetFinding(
            asset_type="ssh_host_key",
            host=host,
            port=port,
            algorithm=algorithm,
            key_type=key_type,
            key_size=key_size,
            fingerprint_sha256=fingerprint_sha256,
            metadata={"banner": banner, "offered_algorithms": host_key_algos},
        )

    # ------------------------------------------------------------------
    # Combined host scan
    # ------------------------------------------------------------------
    def scan_host(self, host: str) -> dict[str, Any]:
        """Scan a single host for both TLS and SSH cryptographic assets.

        Args:
            host: Hostname or IP address.

        Returns:
            A dict with: host, scan_timestamp, tls_findings (list), ssh_findings (list).
        """
        findings: dict[str, Any] = {
            "host": host,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "tls_findings": [],
            "ssh_findings": [],
        }

        # Common TLS ports
        tls_ports = [443, 8443, 993, 995, 636, 465]
        for port in tls_ports:
            try:
                res = self.scan_tls(host, port)
                if res:
                    findings["tls_findings"].append(res.model_dump())
            except Exception:
                continue

        # SSH port
        ssh_result = self.scan_ssh(host, 22)
        if ssh_result:
            findings["ssh_findings"].append(ssh_result.model_dump())

        return findings

    # ------------------------------------------------------------------
    # Network scanning
    # ------------------------------------------------------------------
    def scan_network(self, cidr: str) -> list[dict[str, Any]]:
        """Discover hosts on a network and scan each for crypto assets.

        Args:
            cidr: CIDR network range (e_g "192.168.1.0/24").
        """
        if not self._nm:
            return []
        try:
            self._nm.scan(hosts=cidr, arguments="-sn -T4")
            hosts_up = [h for h in self._nm.all_hosts() if self._nm[h].state() == "up"]
            results: list[dict[str, Any]] = []
            for host in hosts_up:
                try:
                    host_result = self.scan_host(host)
                    results.append(host_result)
                except Exception:
                    pass
            return results
        except Exception:
            return []

    # ------------------------------------------------------------------
    # CBOM generation
    # ------------------------------------------------------------------
    def generate_cbom(self, scan_results: dict[str, Any] | list[dict[str, Any]]) -> dict[str, Any]:
        """Generate a Cryptographic Bill of Materials (CBOM) from scan results.

        Args:
            scan_results: Either a single host scan dict (from scan_int) or
            a list of host scans (from scan_network).
        """
        if isinstance(scan_results, dict):
            host_scans = [scan_results]
        else:
            host_scans = scan_results

        assets: list[dict[str, Any]] = []
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        for host_scan in host_scans:
            host = host_scan.get("host", "unknown")
            if "error" in host_scan:
                continue

            for tls in host_scan.get("tls_findings", []):
                assets.append(self._tls_to_asset(tls, host))

            for ssh in host_scan.get("ssh_findings", []):
                assets.append(self._ssh_to_asset(ssh, host))

            if "scan_timestamp" in host_scan:
                scan_timestamp = scan_timestamp

        return {
            "schema_version": CBOM_SCHEMA_VERSION,
            "scan_timestamp": scan_timestamp,
            "assets": assets,
            "asset_count": len(assets),
        }

    @staticmethod
    def _tls_to_asset(tls: dict[str, Any], host: str) -> dict[str, Any]:
        """Convert a TLS finding to a CBOM asset entry."""
        algorithm = tls.get("algorithm", "unknown")
        key_type = tls.get("key_type", "unknown")
        key_size = tls.get("key_size", 0)
        issuer = tls.get("issuer", "")
        # Extract vendor from issuer CN if possible
        vendor = "unknown"
        if issuer:
            for part in issuer.split(","):
                if "CN=" in part:
                    vendor = part.split("CN=")[-1].strip()
                    break

        criticality = CryptoScanner._assess_criticality(
            key_type, key_size, tls.get("expired", False)
        )
        pqc_ready = algorithm in PQC_ALGORITHMS
        return {
            "type": "tls_certificate",
            "host": host,
            "port": tls.get("port", 443),
            "algorithm": algorithm,
            "key_type": key_type,
            "key_size": key_size,
            "vendor": vendor,
            "criticality": criticality,
            "pqc_ready": pqc_ready,
            "fingerprint_sha256": tls.get("fingerprint_sha256", ""),
            "expired": tls.get("expired", False),
            "not_after": tls.get("not_after", ""),
            "metadata": {
                "issuer": issuer,
                "subject": tls.get("subject", ""),
                "serial": tls.get("serial_number", ""),
            }
        }

    @staticmethod
    def _ssh_to_asset(ssh: dict[str, Any], host: str) -> dict[str, Any]:
        """Convert an SSH finding to a CBOM asset entry."""
        algorithm = ssh.get("algorithm", "unknown")
        key_type = ssh.get("key_type", "unknown")
        key_size = ssh.get("key_size", 0)
        criticality = CryptoScanner._assess_criticality(key_type, key_size, False)
        pqc_ready = algorithm in PQC_ALGORITHMS
        return {
            "type": "ssh_host_key",
            "host": host,
            "port": ssh.get("port", 22),
            "algorithm": algorithm,
            "key_type": key_type,
            "key_size": key_size,
            "vendor": "openssh",
            "criticality": criticality,
            "pqc_ready": pqc_ready,
            "fingerprint_sha256": ssh.get("fingerprint_sha256", ""),
            "metadata": {
                "banner": ssh.get("banner", ""),
                "offered_algorithms": ssh.get("offered_algorithms", []),
            }
        }

    @staticmethod
    def _assess_criticality(key_type: str, key_size: int, expired: bool) -> str:
        """Assess the criticality of a cryptographic asset.

        Returns one of: "Critical", "High", "Medium", "Low".
        """
        if expired:
            return "Critical"

        threshold = WEAK_KEY_THRESHOLDS.get(key_type)
        if threshold is None:
            return "Low"

        if key_size < threshold:
            return "Critical"
        if key_size == threshold:
            return "High"
        if key_size < threshold * 2:
            return "Medium"
        return "Low"

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
    @staticmethod
    def hash_cbom(cbom: dict[str, Any]) -> str:
        """Compute the SHA-256 hash of a CBOM dict (for on-chain registration)."""
        canonical = json.dumps(cbom, sort_keys=True)
        return "0x" + hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def save_cbom(cbom: dict[str, Any], path: str) -> str:
        """Write a CBOM to a file. Returns the path."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cbom, f, indent=2, sort_keys=True)
        return path

def trust_findings_to_dict(finding: Any) -> dict:
    """Helper to convert an AssetFinding to a dict."""
    if hasattr(finding, "model_dump"):
        return finding.model_dump()
    return {}

def scan_host(host: str, ports: list = None) -> ScanResult:
    """Top-level function for scanning a host."""
    scanner = CryptoScanner()
    if ports is None:
        ports = [443, 8443, 22]

    findings = []
    for port in ports:
        if port in (443, 8443):
            res = scanner.scan_tls(host, port)
            if res:
                findings.append(res)
        elif port == 22:
            res = scanner.scan_ssh(host, port)
            if res:
                findings.append(res)

    return ScanResult(
        target=host,
        scanner="qtrust-inspector",
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        started_at=int(datetime.now(timezone.utc).timestamp()),
        completed_at=int(datetime.now(timezone.utc).timestamp()),
        findings=findings
    )

def scan_directory(directory: str) -> ScanResult:
    """Top-level function for scanning a directory."""
    from datetime import datetime, timezone
    findings = []
    for f in scan_pem_files(directory):
        findings.append(f)
    for f in scan_ssh_directory():
        findings.append(f)
    return ScanResult(
        target=directory,
        scanner="qtrust-inspector",
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        started_at=int(datetime.now(timezone.utc).timestamp()),
        completed_at=int(datetime.now(timezone.utc).timestamp()),
        findings=findings
    )

def scan_network(hosts: list, ports: list = None) -> list[ScanResult]:
    """Top-level function for scanning a network."""
    scanner = CryptoScanner()
    if ports is None:
        ports = [443, 8443, 22]

    results = []
    for host in hosts:
        res_dict = scanner.scan_host(host)
        findings = []
        for f in res_dict.get("tls_findings", []) + res_dict.get("ssh_findings", []):
            findings.append(AssetFinding(**f))

        results.append(ScanResult(
            target=host,
            scanner="qtrust-inspector",
            started_at=int(datetime.now(timezone.utc).timestamp()),
            completed_at=int(datetime.now(timezone.utc).timestamp()),
            findings=findings
        ))
    return results
