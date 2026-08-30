"""
AST extraction — §3 Signal C + §42 (§44 evidence fusion).

Combines static lexical (A), API calls (B), AST (C), dependency graph (D), dataflow (E).
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List


SUPPORTED_EXT = {
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".sol": "solidity",
    ".sh": "shell",
}


def extract_python_ast(code: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return findings
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            else:
                names = [a.name for a in node.names] + [node.module or ""]
            blob = " ".join(names)
            if any(kw in blob.lower() for kw in ("crypto", "hashlib", "rsa", "ecdsa", "nacl")):
                findings.append(
                    {"type": "import", "line": getattr(node, "lineno", 1), "evidence": blob, "signal": "AST"}
                )
        if isinstance(node, ast.Call):
            func = ""
            if isinstance(node.func, ast.Attribute):
                func = node.func.attr
            elif isinstance(node.func, ast.Name):
                func = node.func.id
            if func.lower() in ("encrypt", "decrypt", "sign", "verify", "hash", "digest", "generate"):
                findings.append(
                    {"type": "call", "line": getattr(node, "lineno", 1), "evidence": func, "signal": "API"}
                )
        if isinstance(node, ast.ClassDef):
            if any(kw in node.name.lower() for kw in ("crypto", "cipher", "wrapper", "sdk")):
                findings.append(
                    {"type": "class", "line": getattr(node, "lineno", 1), "evidence": node.name, "signal": "AST"}
                )
    return findings


def language_from_path(p: Path) -> str:
    return SUPPORTED_EXT.get(p.suffix.lower(), "unknown")


def extract_signals(path: Path, code: str) -> Dict[str, Any]:
    lang = language_from_path(path)
    signals: Dict[str, Any] = {"language": lang, "lexical": [], "ast": [], "api": []}
    # Lexical (Signal A)
    for kw in ("RSA", "ECDSA", "ECDH", "AES", "SHA256", "ML-KEM", "ML-DSA", "Ed25519", "X25519"):
        if kw.lower() in code.lower():
            signals["lexical"].append(kw)
    # AST (Signal C)
    if lang == "python":
        signals["ast"] = extract_python_ast(code)
    return signals
