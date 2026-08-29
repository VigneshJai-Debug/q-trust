"""Tests for real PCAP TLS extraction, Zeek/Suricata ingestion and binary artifact scanning."""
from __future__ import annotations

import io
import socket
import struct
import tarfile
import zipfile
from pathlib import Path


from qtrust_inspector.binary_scanner import scan_binary, scan_binaries_in_directory
from qtrust_inspector.pcap_scanner import (
    analyze_pcap,
    analyze_suricata_eve,
    analyze_zeek_ssl_log,
    detect_capture_format,
)


# ---------------------------------------------------------------------------
# Synthetic packet builders
# ---------------------------------------------------------------------------

def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, 20 + len(payload), 0x1234, 0x4000, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    return header + payload


def _tcp(sport: int, dport: int, seq: int, payload: bytes, flags: int = 0x18) -> bytes:
    header = struct.pack(
        ">HHIIBBHHH",
        sport, dport, seq, seq + 1, (5 << 4), flags, 65535, 0, 0,
    )
    return header + payload


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + struct.pack(">H", ethertype) + payload


def _vlan_eth(payload: bytes) -> bytes:
    return (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
            + struct.pack(">HHH", 0x8100, 0x0064, 0x0800) + payload)


def build_client_hello(
    ciphers: tuple[int, ...] = (0x1301,),
    groups: tuple[int, ...] = (0x001D, 0x11EC),
    sni: str = "example.com",
    sigalgs: tuple[int, ...] = (0x0403, 0x0804, 0x0807),
) -> bytes:
    extensions = b""
    sni_bytes = sni.encode("ascii")
    sni_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    extensions += struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    groups_data = b"".join(struct.pack(">H", g) for g in groups)
    groups_list = struct.pack(">H", len(groups_data)) + groups_data
    extensions += struct.pack(">HH", 0x000A, len(groups_list)) + groups_list

    sigalgs_data = b"".join(struct.pack(">H", s) for s in sigalgs)
    sigalgs_list = struct.pack(">H", len(sigalgs_data)) + sigalgs_data
    extensions += struct.pack(">HH", 0x000D, len(sigalgs_list)) + sigalgs_list

    key_share = struct.pack(">HH", 0x001D, 32) + b"\x11" * 32
    ks_list = struct.pack(">H", len(key_share)) + key_share
    extensions += struct.pack(">HH", 0x0033, len(ks_list)) + ks_list

    sv_list = b"\x02\x03\x04"
    extensions += struct.pack(">HH", 0x002B, len(sv_list)) + sv_list
    assert len(extensions) >= 0 or sv_list

    ciphers_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", len(ciphers_bytes)) + ciphers_bytes
        + b"\x01\x00"
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def build_server_hello(
    cipher: int = 0x1302,
    group: int = 0x11EC,
    selected_version: int = 0x0304,
) -> bytes:
    extensions = b""
    extensions += struct.pack(">HH", 0x002B, 2) + struct.pack(">H", selected_version)
    key_share = struct.pack(">HH", group, 32) + b"\x22" * 32
    extensions += struct.pack(">HH", 0x0033, len(key_share)) + key_share
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", cipher)
        + b"\x00"
        + struct.pack(">H", len(extensions)) + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def _frame(tls_record: bytes, src="10.0.0.5", dst="93.184.216.34",
           sport=49231, dport=443, seq=1) -> bytes:
    ip = _ipv4(src, dst, 6, _tcp(sport, dport, seq, tls_record))
    return _eth(ip)


def _pcap(frames: list[bytes], linktype: int = 1) -> bytes:
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    ts = 1700000000
    for i, frame in enumerate(frames):
        out += struct.pack("<IIII", ts + i, 0, len(frame), len(frame))
        out += frame
    return bytes(out)


def _pcapng(frames: list[bytes], linktype: int = 1) -> bytes:
    out = bytearray()

    def block(btype: int, body: bytes) -> None:
        total = 12 + len(body)
        pad = (-len(body)) % 4
        total += pad
        out.extend(struct.pack("<II", btype, total) + body + b"\x00" * pad + struct.pack("<I", total))

    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    block(0x0A0D0D0A, shb_body)
    block(0x00000001, struct.pack("<HHI", linktype, 0, 65535))
    ts_high = 0
    ts_low = 1700000000
    for frame in frames:
        epb_body = struct.pack("<IIIII", 0, ts_high, ts_low, len(frame), len(frame)) + frame
        block(0x00000006, epb_body)
    return bytes(out)


def _write(tmp_path: Path, name: str, blob: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(blob)
    return p


# ---------------------------------------------------------------------------
# PCAP TLS extraction
# ---------------------------------------------------------------------------

class TestPcapTLSExtraction:
    def test_client_hello_cipher_groups_sni(self, tmp_path: Path):
        ch = build_client_hello(ciphers=(0x1301,), groups=(0x001D, 0x11EC), sni="example.com")
        path = _write(tmp_path, "ch.pcap", _pcap([_frame(ch)]))
        result = analyze_pcap(path)
        assert "error" not in result
        assert result["total_flows"] == 1
        flow = result["flows"][0]
        assert flow["cipher_suite"] == "TLS_AES_128_GCM_SHA256"
        assert "x25519" in flow["supported_groups"]
        assert "X25519MLKEM768" in flow["supported_groups"]
        assert flow["sni"] == "example.com"
        assert flow["pq_hybrid"] is True
        assert flow["cipher_extraction"] is True
        assert flow["protocol"] == "TLSv1.3"

    def test_client_hello_over_vlan_and_pcapng(self, tmp_path: Path):
        ch = build_client_hello()
        path = _write(tmp_path, "ch.pcapng", _pcapng([_frame(ch)]))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1
        assert result["flows"][0]["sni"] == "example.com"

    def test_vlan_tagged_frame(self, tmp_path: Path):
        ch = build_client_hello()
        ip = _ipv4("10.0.0.5", "93.184.216.34", 6, _tcp(50000, 443, 1, ch))
        path = _write(tmp_path, "vlan.pcap", _pcap([_vlan_eth(ip)]))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1
        assert result["flows"][0]["cipher_suite"] == "TLS_AES_128_GCM_SHA256"

    def test_server_hello_chosen_suite(self, tmp_path: Path):
        sh = build_server_hello(cipher=0x1302, group=0x11EC)
        path = _write(tmp_path, "sh.pcap", _pcap([_frame(sh)]))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1
        flow = result["flows"][0]
        assert flow["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert flow["negotiated_group"] == "X25519MLKEM768"
        assert flow["pq_hybrid"] is True
        assert flow["tls_version"] == "TLSv1.3"

    def test_segmented_handshake_with_retransmit(self, tmp_path: Path):
        ch = build_client_hello()
        first, second = ch[:20], ch[20:]
        dup_of_second = second
        frames = [
            _frame(first, seq=1),
            _frame(second, seq=21),
            _frame(dup_of_second, seq=21),
        ]
        path = _write(tmp_path, "seg.pcap", _pcap(frames))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1
        flow = result["flows"][0]
        assert flow["cipher_extraction"] is True
        assert flow["sni"] == "example.com"

    def test_classical_rsa_suite_scores_worst_case(self, tmp_path: Path):
        ch = build_client_hello(ciphers=(0x009C,), groups=(0x0017,))
        sh = build_server_hello(cipher=0x009C, group=0x0017, selected_version=0x0303)
        path = _write(tmp_path, "rsa.pcap", _pcap([_frame(ch), _frame(sh, seq=1 + len(ch))]))
        result = analyze_pcap(path)
        flow = result["flows"][0]
        assert flow["cipher_suite"] == "TLS_RSA_WITH_AES_128_GCM_SHA256"
        assert flow["negotiated_group"] == "secp256r1"
        assert flow["pq_hybrid"] is False
        assert flow["vulnerability"] == "BROKEN"
        hybrid_score = 100 * 0.25 * 0.94
        assert flow["hndl_score"] > hybrid_score

    def test_midstream_tls_flags_cipher_extraction_false(self, tmp_path: Path):
        appdata = b"\x17\x03\x03\x00\x05hello"
        path = _write(tmp_path, "mid.pcap", _pcap([_frame(appdata)]))
        result = analyze_pcap(path)
        flow = result["flows"][0]
        assert flow["cipher_extraction"] is False
        assert flow["cipher_suite"] == ""
        assert flow["recommendations"]

    def test_ssh_banner_flow(self, tmp_path: Path):
        banner = b"SSH-2.0-OpenSSH_9.6\r\n"
        path = _write(tmp_path, "ssh.pcap", _pcap([_frame(banner, dport=22)]))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1
        assert result["flows"][0]["protocol"] == "SSH"

    def test_nanosecond_magic_supported(self, tmp_path: Path):
        ch = build_client_hello()
        pcap_le_ns = bytearray(_pcap([_frame(ch)]))
        pcap_le_ns[0:4] = b"\x4d\x3c\xb2\xa1"
        path = _write(tmp_path, "ns.pcap", bytes(pcap_le_ns))
        result = analyze_pcap(path)
        assert result["total_flows"] == 1

    def test_packet_caps_respected(self, tmp_path: Path):
        from qtrust_inspector import pcap_scanner
        ch = build_client_hello()
        data = _pcap([_frame(ch, seq=1 + i * 1000) for i in range(5)])
        packets = list(pcap_scanner.iter_capture_packets(io.BytesIO(data), max_packets=2, max_bytes=1 << 30))
        assert len(packets) == 2

    def test_nonexistent_file_error_shape(self):
        result = analyze_pcap("/nonexistent/capture.pcap")
        assert "error" in result
        assert result["flows"] == []

    def test_summary_keys_for_cli(self, tmp_path: Path):
        ch = build_client_hello()
        path = _write(tmp_path, "cli.pcap", _pcap([_frame(ch)]))
        result = analyze_pcap(path, deep_scan=True, top_n=10)
        summary = result["summary"]
        assert summary["total_flows"] == 1
        assert summary["high_risk_flows"] >= 0
        assert isinstance(summary["average_hndl_score"], float)

    def test_deep_scan_extra_fields(self, tmp_path: Path):
        ch = build_client_hello(sigalgs=(0x0905,))
        path = _write(tmp_path, "deep.pcap", _pcap([_frame(ch)]))
        result = analyze_pcap(path, deep_scan=True)
        flow = result["flows"][0]
        assert "MLDSA65" in flow["signature_algorithms"]
        assert flow["offered_ciphers"] == ["TLS_AES_128_GCM_SHA256"]


# ---------------------------------------------------------------------------
# Zeek / Suricata ingestion
# ---------------------------------------------------------------------------

ZEEK_TSV = (
    "#separator \\x09\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tcipher\tcurve\tserver_name\tvalidation_status\n"
    "1700000000.1\tCabc123\t10.0.0.5\t49231\t93.184.216.34\t443\tTLSv13\tTLS_AES_256_GCM_SHA384\tx25519mlkem768\texample.com\tok\n"
    "1700000001.9\tCdef456\t10.0.0.6\t50777\t198.51.100.7\t993\tTLSv12\tECDHE-RSA-AES128-GCM-SHA256\tx25519\tmail.example.org\tcertificate invalid\n"
)

ZEEK_JSON = "\n".join([
    '{"ts":1700000000.1,"uid":"Cabc","id":{"orig_h":"10.0.0.5","orig_p":49231,"resp_h":"93.184.216.34","resp_p":443},'
    '"version":"TLSv13","cipher":"TLS_AES_128_GCM_SHA256","curve":"X25519MLKEM768","server_name":"example.com","validation_status":"ok"}',
    '{"ts":1700000001.0,"uid":"Cabd","id":{"orig_h":"10.0.0.7","orig_p":40000,"resp_h":"203.0.113.9","resp_p":443},'
    '"version":"TLSv13","cipher":"TLS_AES_256_GCM_SHA384","server_name":"safe.example.net"}',
]) + "\n"


class TestZeekIngestion:
    def test_tsv_two_flows_normalized(self, tmp_path: Path):
        path = _write(tmp_path, "ssl.log", ZEEK_TSV.encode())
        result = analyze_zeek_ssl_log(path)
        assert result["format"] == "zeek"
        assert result["total_flows"] == 2
        flows = {f["dst_port"]: f for f in result["flows"]}
        pq_flow = flows[443]
        assert pq_flow["source"] == "zeek"
        assert pq_flow["sni"] == "example.com"
        assert pq_flow["cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert pq_flow["negotiated_group"] == "X25519MLKEM768"
        assert pq_flow["pq_hybrid"] is True
        mail_flow = flows[993]
        assert mail_flow["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        assert mail_flow["pq_hybrid"] is False
        assert mail_flow["validation_status"] == "certificate invalid"

    def test_json_variant(self, tmp_path: Path):
        path = _write(tmp_path, "ssl.json.log", ZEEK_JSON.encode())
        result = analyze_zeek_ssl_log(path)
        assert result["total_flows"] == 2
        by_sni = {f["sni"]: f for f in result["flows"]}
        assert by_sni["example.com"]["pq_hybrid"] is True
        assert by_sni["safe.example.net"]["hndl_score"] > 0

    def test_auto_detect_routes_to_zeek(self, tmp_path: Path):
        path = _write(tmp_path, "capture.log", ZEEK_TSV.encode())
        assert detect_capture_format(path) == "zeek"
        result = analyze_pcap(path)
        assert result["format"] == "zeek"
        assert result["total_flows"] == 2


SURICATA_EVE = "\n".join([
    '{"timestamp":"2026-01-01T00:00:00","event_type":"tls","src_ip":"10.0.0.5","src_port":50000,'
    '"dest_ip":"1.2.3.4","dest_port":443,"tls":{"sni":"example.com","version":"TLS 1.3",'
    '"subject":"CN=example.com","issuerdn":"CN=R3","ja3":{"hash":"aabbcc"}}}',
    '{"timestamp":"2026-01-01T00:00:01","event_type":"alert","src_ip":"10.0.0.5","src_port":50001,'
    '"dest_ip":"1.2.3.4","dest_port":443,"alert":{"signature":"test"}}',
    '{"timestamp":"2026-01-01T00:00:02","event_type":"tls","src_ip":"10.0.0.9","src_port":51000,'
    '"dest_ip":"5.6.7.8","dest_port":443,"tls":{"sni":"other.example.org","version":"TLS 1.2"}}',
]) + "\n"


class TestSuricataIngestion:
    def test_eve_tls_events_filtered_and_normalized(self, tmp_path: Path):
        path = _write(tmp_path, "eve.json", SURICATA_EVE.encode())
        result = analyze_suricata_eve(path)
        assert result["format"] == "suricata"
        assert result["total_flows"] == 2
        by_sni = {f["sni"]: f for f in result["flows"]}
        assert set(by_sni) == {"example.com", "other.example.org"}
        assert by_sni["example.com"]["tls_version"] == "TLSv1.3"
        assert by_sni["example.com"]["source"] == "suricata"
        assert by_sni["other.example.org"]["cipher_extraction"] is False

    def test_auto_detect_routes_to_suricata(self, tmp_path: Path):
        path = _write(tmp_path, "eve.jsonl", SURICATA_EVE.encode())
        assert detect_capture_format(path) == "suricata"
        result = analyze_pcap(path)
        assert result["total_flows"] == 2

    def test_mcp_scan_binary_tool_handler(self, tmp_path: Path):
        from qtrust_inspector.mcp_server import _handle_tool_call
        elf = b"\x7fELF" + b"\x00" * 16 + b"OpenSSL 3.0.13 11 Feb 2025"
        path = _write(tmp_path, "lib.so", elf)
        res = _handle_tool_call("scan_binary", {"path": str(path)})
        assert res["count"] >= 1
        assert any(f["vendor"] == "OpenSSL" for f in res["findings"])

    def test_mcp_scan_pcap_accepts_format(self, tmp_path: Path):
        from qtrust_inspector.mcp_server import _handle_tool_call
        path = _write(tmp_path, "eve.json", SURICATA_EVE.encode())
        res = _handle_tool_call("scan_pcap", {"path": str(path), "format": "suricata"})
        assert res["summary"]["total_flows"] == 2


# ---------------------------------------------------------------------------
# Binary scanner
# ---------------------------------------------------------------------------

class TestBinaryScannerELFPE:
    def test_elf_openssl_version_detected(self, tmp_path: Path):
        blob = b"\x7fELF" + b"\x00" * 24 + b"OpenSSL 3.0.13 11 Feb 2025"
        path = _write(tmp_path, "libcrypto.so.bin", blob)
        findings = scan_binary(path)
        openssl = [f for f in findings if f.vendor == "OpenSSL"]
        assert len(openssl) == 1
        f = openssl[0]
        assert f.asset_type == "binary_crypto_artifact"
        assert f.metadata["library"] == "OpenSSL"
        assert f.metadata["version"] == "3.0.13"
        assert f.metadata["offset"] > 0
        assert f.metadata["format"] == "ELF"

    def test_elf_static_symbol_fallback(self, tmp_path: Path):
        blob = b"\x7fELF" + b"\x00" * 40 + b"EVP_CIPHER_CTX_new"
        path = _write(tmp_path, "nostrings.so", blob)
        findings = scan_binary(path)
        assert any(f.vendor == "OpenSSL" for f in findings)

    def test_openssl_1_1_1_flagged_classical_only(self, tmp_path: Path):
        blob = b"\x7fELF" + b"\x00" * 8 + b"OpenSSL 1.1.1w  11 Sep 2023"
        path = _write(tmp_path, "oldssl", blob)
        findings = scan_binary(path)
        f = next(f for f in findings if f.vendor == "OpenSSL")
        assert f.metadata["supports_pqc"] is False
        assert "classical" in f.metadata["note"]
        assert f.criticality == "high"

    def test_pe_dll_import_hint(self, tmp_path: Path):
        blob = b"MZ" + b"\x00" * 60 + b"libcrypto-3.dll\x00libssl-3.dll\x00bcryptprimitives.dll"
        path = _write(tmp_path, "app.exe", blob)
        findings = scan_binary(path)
        hints = [f for f in findings if f.metadata.get("import_hint")]
        assert hints
        assert all("bcryptprimitives" not in (f.metadata.get("import_hint") or "") for f in hints)
        assert any(f.metadata.get("import_hint") == "libcrypto-3.dll" for f in hints)

    def test_macho_boringssl(self, tmp_path: Path):
        blob = b"\xcf\xfa\xed\xfe" + b"\x00" * 28 + b"BoringSSL static build"
        path = _write(tmp_path, "chrome.dylib", blob)
        findings = scan_binary(path)
        assert any(f.vendor == "BoringSSL" for f in findings)

    def test_embedded_pem_private_key_critical(self, tmp_path: Path):
        pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n"
        blob = b"\x7fELF" + b"\xff" * 10 + pem
        path = _write(tmp_path, "firmware.bin", blob)
        findings = scan_binary(path)
        key_findings = [f for f in findings if f.algorithm == "RSA"]
        assert key_findings
        assert key_findings[0].criticality == "critical"


class TestBinaryScannerZip:
    def test_jar_bouncycastle_detection(self, tmp_path: Path):
        jar_path = tmp_path / "app.jar"
        with zipfile.ZipFile(jar_path, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            zf.writestr("org/bouncycastle/jce/X.class", b"\xca\xfe\xba\xbe")
            zf.writestr("org/bouncycastle/jce/provider/BouncyCastleProvider.class", b"\xca\xfe\xba\xbe")
        findings = scan_binary(jar_path)
        bc = [f for f in findings if f.vendor == "BouncyCastle"]
        assert len(bc) == 1
        assert bc[0].asset_type == "binary_crypto_artifact"
        assert bc[0].metadata["entry_example"].startswith("org/bouncycastle/")

    def test_jar_signature_keystore_and_native_lib(self, tmp_path: Path):
        jar_path = tmp_path / "app.apk"
        with zipfile.ZipFile(jar_path, "w") as zf:
            zf.writestr("META-INF/CERT.RSA", b"signed")
            zf.writestr("assets/app.keystore", b"keystore-bytes")
            zf.writestr("lib/arm64-v8a/libcrypto.so", b"\x7fELF")
        findings = scan_binary(jar_path)
        algorithms = {f.algorithm for f in findings}
        assert "jar-signature" in algorithms
        assert "java-keystore" in algorithms
        assert any(f.metadata.get("library") == "OpenSSL" and f.metadata.get("entry") for f in findings)

    def test_wheel_requires_dist_cryptography(self, tmp_path: Path):
        wheel_path = tmp_path / "pkg-1.0-py3-none-any.whl"
        metadata = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\nRequires-Dist: cryptography (>=42.0)\nRequires-Dist: requests\n"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("pkg/__init__.py", "")
            zf.writestr("pkg-1.0.dist-info/METADATA", metadata)
        findings = scan_binary(wheel_path)
        crypto = [f for f in findings if f.metadata.get("library") == "cryptography"]
        assert len(crypto) == 1
        assert crypto[0].metadata.get("version") == "42.0"

    def test_gem_archive_scanned(self, tmp_path: Path):
        gemspec = 'Gem::Specification.new do |s|\n  s.name = "crypto-helper"\n  s.summary = "openssl bindings"\nend'
        inner_buf = io.BytesIO()
        with tarfile.open(fileobj=inner_buf, mode="w:gz") as inner:
            spec_bytes = gemspec.encode()
            info = tarfile.TarInfo("crypto-helper-1.0.gemspec")
            info.size = len(spec_bytes)
            inner.addfile(info, io.BytesIO(spec_bytes))
        outer_buf = io.BytesIO()
        with tarfile.open(fileobj=outer_buf, mode="w") as outer:
            inner_data = inner_buf.getvalue()
            info = tarfile.TarInfo("data.tar.gz")
            info.size = len(inner_data)
            outer.addfile(info, io.BytesIO(inner_data))
        path = _write(tmp_path, "crypto-helper.gem", outer_buf.getvalue())
        findings = scan_binary(path)
        assert any(f.metadata.get("library") == "crypto-helper" for f in findings)


class TestBinaryDirectoryScan:
    def test_directory_scan_skips_and_symlinks(self, tmp_path: Path):
        root = tmp_path / "tree"
        (root / ".git").mkdir(parents=True)
        (root / "node_modules").mkdir()
        (root / "target").mkdir()
        good = root / "libs"
        good.mkdir()
        (good / "libreal.so").write_bytes(b"\x7fELF" + b"\x00" * 8 + b"wolfSSL 5.7.0")
        (root / ".git" / "hooked").write_bytes(b"\x7fELF" + b"OpenSSL 3.0.13 11 Feb 2025")
        (root / "node_modules" / "native.node").write_bytes(b"\x7fELF" + b"mbed TLS 3.5.2")
        try:
            (root / "link.so").symlink_to(good / "libreal.so")
        except OSError:
            pass
        empty = root / "empty.bin"
        empty.write_bytes(b"")

        findings = scan_binaries_in_directory(root)
        vendors = {f.vendor for f in findings}
        assert "wolfSSL" in vendors
        assert "OpenSSL" not in vendors
        assert "mbedTLS" not in vendors

    def test_max_file_size_cap(self, tmp_path: Path):
        big = tmp_path / "huge.so"
        big.write_bytes(b"\x7fELF" + b"\x00" * (70 * 1024 * 1024) + b"OpenSSL 3.0.13")
        small = tmp_path / "small.so"
        small.write_bytes(b"\x7fELF" + b"OpenSSL 3.0.13 11 Feb 2025")
        findings_capped = scan_binaries_in_directory(tmp_path, max_file_size=1024)
        assert {f.host for f in findings_capped} == {str(small)}
        findings_default = scan_binaries_in_directory(tmp_path, max_file_size=64 * 1024 * 1024)
        assert all(f.host != str(big) for f in findings_default)


# ---------------------------------------------------------------------------
# Classification sanity via public API
# ---------------------------------------------------------------------------

class TestClassificationUpgrade:
    def test_unknown_capture_stays_conservative_but_flagged(self, tmp_path: Path):
        appdata = b"\x17\x03\x03\x00\x10" + b"A" * 16
        path = _write(tmp_path, "opaque.pcap", _pcap([_frame(appdata)]))
        result = analyze_pcap(path)
        flow = result["flows"][0]
        assert flow["cipher_extraction"] is False
        assert flow["vulnerability"] == "BROKEN"
        assert flow["risk_level"] in ("CRITICAL", "HIGH")

    def test_hybrid_negotiation_scores_lower_than_classical(self, tmp_path: Path):
        hybrid_sh = build_server_hello(cipher=0x1302, group=0x11EC)
        classical_sh = build_server_hello(cipher=0xC02F, group=0x001D, selected_version=0x0303)
        hybrid_result = analyze_pcap(_write(tmp_path, "hyb.pcap", _pcap([_frame(hybrid_sh)])))
        classical_result = analyze_pcap(_write(tmp_path, "cls.pcap", _pcap([_frame(classical_sh)])))
        hyb = hybrid_result["flows"][0]
        cls = classical_result["flows"][0]
        assert hyb["pq_hybrid"] is True
        assert cls["pq_hybrid"] is False
        assert hyb["hndl_score"] < cls["hndl_score"]
        assert cls["vulnerability"] == "BROKEN"
