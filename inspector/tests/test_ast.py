"""Tests for real AST-based cryptographic API detection."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qtrust_inspector.ast_scanner import (
    DETECTOR_CAPABILITIES,
    merge_findings_dedupe,
    scan_file_ast,
    scan_source_directory_ast,
    scan_with_ast,
)
from qtrust_inspector.cli import app
from qtrust_inspector.models import AssetFinding

RUNNER = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_RUNNER = REPO_ROOT / "backend" / "scripts" / "run_inspector.py"

PY_SNIPPET = """import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa


def hash_token(token: bytes) -> str:
    digest = hashlib.md5(token).hexdigest()
    return digest


def load_signing_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key
"""


class TestDetectorCapabilities:
    def test_python_capability_is_stdlib_ast(self):
        assert DETECTOR_CAPABILITIES["python"] == "stdlib-ast"

    def test_javascript_capability_is_honest_label(self):
        assert DETECTOR_CAPABILITIES["javascript"] in {"tree-sitter", "regex-fallback"}
        assert DETECTOR_CAPABILITIES["typescript"] in {"tree-sitter", "regex-fallback"}

    def test_other_languages_are_regex_fallback(self):
        for lang in ("go", "java", "rust", "c", "cpp", "csharp"):
            assert DETECTOR_CAPABILITIES[lang] == "regex-fallback"


class TestPythonAstDetection:
    def _scan_snippet(
        self,
        tmp_path: Path,
        code: str,
        name: str = "service.py",
    ) -> list[AssetFinding]:
        target = tmp_path / name
        target.write_text(code)
        return scan_file_ast(target)

    def test_md5_and_rsa_with_line_and_scope(self, tmp_path):
        findings = self._scan_snippet(tmp_path, PY_SNIPPET)
        assert findings, "expected at least one finding"
        md5_findings = [f for f in findings if f.algorithm == "MD5"]
        rsa_findings = [f for f in findings if f.algorithm and f.algorithm.startswith("RSA")]
        assert len(md5_findings) == 1
        assert len(rsa_findings) == 1
        m, r = md5_findings[0], rsa_findings[0]
        assert m.metadata["detector"] == "ast-python"
        assert m.metadata["line"] == 6
        assert m.metadata["scope"] == "hash_token"
        assert m.asset_type == "source_crypto_usage"
        assert r.metadata["detector"] == "ast-python"
        assert r.metadata["line"] == 11
        assert r.metadata["scope"] == "load_signing_key"
        assert r.metadata["end_lineno"] == 11
        assert r.key_type == "asymmetric"

    def test_hashlib_new_constant_string(self, tmp_path):
        code = (
            "import hashlib\n"
            "\n"
            "def weak(data):\n"
            "    return hashlib.new('md5', data)\n"
        )
        findings = self._scan_snippet(tmp_path, code)
        assert [f.algorithm for f in findings] == ["MD5"]
        assert findings[0].metadata["line"] == 4
        assert findings[0].metadata["scope"] == "weak"

    def test_variable_named_rsa_size_not_flagged(self, tmp_path):
        code = (
            "rsa_size = 2048\n"
            'msg = "sha256(x) is a strong hash"\n'
            "\n"
            "def helper(v):\n"
            "    return v\n"
        )
        assert self._scan_snippet(tmp_path, code) == []

    def test_unbound_name_not_flagged(self, tmp_path):
        code = "rsa = 42\nprint(rsa)\n"
        assert self._scan_snippet(tmp_path, code) == []

    def test_jwt_hs256_maps_to_hmac_sha256(self, tmp_path):
        code = (
            "import jwt\n"
            "\n"
            "def make(payload):\n"
            "    return jwt.encode(payload, 'k', algorithm='HS256')\n"
        )
        findings = self._scan_snippet(tmp_path, code)
        assert [f.algorithm for f in findings] == ["HMAC-SHA256"]

    def test_ec_curve_refinement(self, tmp_path):
        code = (
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "\n"
            "def gen():\n"
            "    return ec.generate_private_key(curve=ec.SECP256R1())\n"
        )
        findings = self._scan_snippet(tmp_path, code)
        assert [f.algorithm for f in findings] == ["ECDSA-P256"]

    def test_ssl_weak_cipher_constant(self, tmp_path):
        code = (
            "import ssl\n"
            "\n"
            "def configure(ctx):\n"
            "    ctx.set_ciphers('DES-CBC3-SHA:RC4-SHA')\n"
        )
        findings = self._scan_snippet(tmp_path, code)
        algos = {f.algorithm for f in findings}
        assert {"3DES", "RC4"} <= algos
        assert all(f.key_type == "tls-cipher-suite" for f in findings)

    def test_test_file_marked_in_metadata(self, tmp_path):
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        target = tests_dir / "test_crypto.py"
        target.write_text(PY_SNIPPET)
        findings = scan_file_ast(target)
        assert findings
        assert all(f.metadata["in_test"] is True for f in findings)
        assert all(f.criticality == "medium" for f in findings)

    def test_production_file_high_criticality(self, tmp_path):
        findings = self._scan_snippet(tmp_path, PY_SNIPPET)
        assert all(f.criticality == "high" for f in findings)

    def test_class_scope_recorded(self, tmp_path):
        code = (
            "import hashlib\n"
            "\n"
            "\n"
            "class Vault:\n"
            "    def fingerprint(self, data):\n"
            "        return hashlib.md5(data).hexdigest()\n"
        )
        findings = self._scan_snippet(tmp_path, code)
        assert len(findings) == 1
        assert findings[0].metadata["scope"] == "Vault.fingerprint"
        assert findings[0].metadata["function"] == "fingerprint"

    def test_syntax_error_falls_back_to_regex(self, tmp_path):
        code = "def broken(:\n    hashlib.md5()\n"
        findings = self._scan_snippet(tmp_path, code)
        assert all(f.metadata["detector"] == "regex-fallback" for f in findings)


class TestJavaScriptFallback:
    def _scan_js(self, tmp_path: Path, code: str, name: str = "app.js") -> list[AssetFinding]:
        target = tmp_path / name
        target.write_text(code)
        return scan_file_ast(target)

    def test_fallback_detector_label_present(self, tmp_path):
        code = (
            "// demo\n"
            "const crypto = require('crypto');\n"
            "const h = crypto.createHash('md5').update('x').digest('hex');\n"
            "const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });\n"
        )
        findings = self._scan_js(tmp_path, code)
        assert findings
        expected_detector = DETECTOR_CAPABILITIES["javascript"]
        for finding in findings:
            assert finding.metadata["detector"] in {"tree-sitter-js", "regex-fallback"}
            assert finding.metadata["detector"] == expected_detector
        algos = {f.algorithm for f in findings}
        assert {"MD5", "RSA"} <= algos

    def test_string_literal_containing_call_not_flagged(self, tmp_path):
        code = "const s = 'crypto.createHash(\"md5\")';\nconsole.log(s);\n"
        assert self._scan_js(tmp_path, code) == []

    def test_commented_call_not_flagged(self, tmp_path):
        code = "// crypto.createHash('md5');\nconst x = 1;\n"
        assert self._scan_js(tmp_path, code) == []

    def test_subtle_encrypt_scope(self, tmp_path):
        code = (
            "async function enc(data) {\n"
            "  return crypto.subtle.encrypt({ name: 'AES-GCM' }, key, data);\n"
            "}\n"
        )
        findings = self._scan_js(tmp_path, code)
        assert len(findings) == 1
        assert findings[0].algorithm == "AES"
        assert findings[0].metadata["scope"] == "enc"

    def test_typescript_uses_same_pipeline(self, tmp_path):
        code = "const h = require('crypto').createHash('sha1');\n"
        findings = self._scan_js(tmp_path, code, name="util.ts")
        assert any(f.algorithm == "SHA-1" for f in findings)


class TestDirectoryScanAndMerge:
    def test_scan_source_directory_ast(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "crypto_util.py").write_text(PY_SNIPPET)
        (src / "plain.py").write_text("x = 1\n")
        node_modules = src / "node_modules"
        node_modules.mkdir()
        (node_modules / "dep.js").write_text("const h = require('crypto').createHash('md5');\n")
        findings = scan_source_directory_ast(str(src))
        hosts = {f.host for f in findings}
        assert str(src / "crypto_util.py") in hosts
        assert not any("node_modules" in h for h in hosts)

    def test_merge_findings_dedupe_by_location_algorithm_line(self):
        base = [
            AssetFinding(
                asset_type="source_crypto_usage",
                host="a.py",
                algorithm="MD5",
                metadata={"line": 3},
            ),
        ]
        duplicate = AssetFinding(
            asset_type="source_crypto_usage",
            host="a.py",
            algorithm="MD5",
            metadata={"line": 3},
        )
        distinct = AssetFinding(
            asset_type="source_crypto_usage",
            host="a.py",
            algorithm="MD5",
            metadata={"line": 9},
        )
        merged = merge_findings_dedupe(base, [duplicate, distinct])
        assert len(merged) == 2

    def test_cli_directory_ast_flag_on_by_default(self, tmp_path):
        (tmp_path / "svc.py").write_text(
            "import hashlib\n\n\ndef run(d):\n    return hashlib.md5(d)\n"
        )
        result = RUNNER.invoke(app, ["directory", "--no-binaries", str(tmp_path)])
        assert result.exit_code == 0
        assert "MD5" in result.output


class TestCliDetectors:
    def test_detectors_flag_prints_valid_json(self):
        result = RUNNER.invoke(app, ["--detectors"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert isinstance(payload, dict)
        assert payload["python"] == "stdlib-ast"

    def test_scan_command_still_works_without_detectors_flag(self):
        result = RUNNER.invoke(app, ["--help"])
        assert result.exit_code == 0


class TestBackwardCompat:
    def test_scan_with_ast_python_content(self, tmp_path):
        findings = scan_with_ast(tmp_path / "inline.py", PY_SNIPPET, "python")
        detectors = {f.metadata["detector"] for f in findings}
        assert detectors == {"ast-python"}

    def test_scan_file_ast_skips_missing_files(self, tmp_path):
        assert scan_file_ast(tmp_path / "does_not_exist.py") == []


class TestMcpIntegration:
    def test_get_detector_capabilities_tool(self):
        from qtrust_inspector.mcp_server import _handle_tool_call

        result = _handle_tool_call("get_detector_capabilities", {})
        assert result["capabilities"]["python"] == "stdlib-ast"

    def test_scan_source_py_file_uses_ast_detector(self, tmp_path):
        from qtrust_inspector.mcp_server import _handle_tool_call

        target = tmp_path / "widget.py"
        target.write_text(PY_SNIPPET)
        result = _handle_tool_call("scan_source", {"path": str(target)})
        assert result["count"] >= 1
        detectors = {f["metadata"]["detector"] for f in result["findings"]}
        assert "ast-python" in detectors


@pytest.mark.skipif(not BACKEND_RUNNER.exists(), reason="backend runner script not present")
class TestBackendRunner:
    def test_ast_passthrough_tags_findings(self, tmp_path):
        (tmp_path / "handler.py").write_text(
            "import hashlib\n\n\ndef digest(payload):\n    return hashlib.md5(payload)\n"
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(BACKEND_RUNNER),
                "--scan-type",
                "source",
                "--path",
                str(tmp_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["findings"]
        ast_findings = [
            f for f in payload["findings"]
            if f.get("metadata", {}).get("detector") == "ast-python"
        ]
        assert ast_findings
        line_values = {f["metadata"]["line"] for f in ast_findings}
        assert 5 in line_values
        assert payload["detector"]["python"] == "stdlib-ast"

    def test_no_ast_flag_disables_ast_layer(self, tmp_path):
        (tmp_path / "handler.py").write_text(
            "import hashlib\n\n\ndef digest(payload):\n    return hashlib.md5(payload)\n"
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(BACKEND_RUNNER),
                "--scan-type",
                "source",
                "--no-ast",
                "--path",
                str(tmp_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert "detector" not in payload
        assert all(
            f.get("metadata", {}).get("detector") != "ast-python"
            for f in payload["findings"]
        )
