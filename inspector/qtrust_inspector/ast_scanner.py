"""Real AST-based cryptographic API detection with honest detector labeling.

Python files are parsed with the stdlib ``ast`` module (always available, zero
extra dependencies). JavaScript/TypeScript files use ``tree_sitter`` when the
``tree-sitter`` package and language packs are importable; otherwise a
structural regex pass runs over comment/string-masked source with
statement-boundary guards. Every finding records the detector that produced
it in ``metadata["detector"]`` so downstream consumers can weigh precision.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .models import AssetFinding
from .source_scanner import SKIP_EXTENSIONS, SKIP_PATTERNS

ASSET_TYPE = "source_crypto_usage"
DETECTOR_PYTHON = "ast-python"
DETECTOR_TREE_SITTER = "tree-sitter-js"
DETECTOR_REGEX_FALLBACK = "regex-fallback"

PY_AST_EXTENSIONS = {".py"}
JS_AST_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

TEST_DIRECTORY_NAMES = {"tests", "test", "__tests__", "spec", "specs"}

KNOWN_CRYPTO_ROOT_MODULES = {"hashlib", "ssl", "hmac", "jwt"}

PY_HASH_FUNCTIONS: dict[str, tuple[str, str]] = {
    "md5": ("MD5", "hash"),
    "sha1": ("SHA-1", "hash"),
    "sha256": ("SHA-256", "hash"),
    "sha384": ("SHA-384", "hash"),
    "sha512": ("SHA-512", "hash"),
    "sha3_256": ("SHA3-256", "hash"),
    "sha3_384": ("SHA3-384", "hash"),
    "sha3_512": ("SHA3-512", "hash"),
}

CONST_HASH_NAMES: dict[str, tuple[str, str]] = {
    **PY_HASH_FUNCTIONS,
    "des": ("DES", "symmetric"),
    "des3": ("3DES", "symmetric"),
    "3des": ("3DES", "symmetric"),
    "aes": ("AES", "symmetric"),
    "rc4": ("RC4", "symmetric"),
    "arc4": ("RC4", "symmetric"),
}

PY_HASH_CLASSES: dict[str, tuple[str, str]] = dict(PY_HASH_FUNCTIONS)

JWT_ALGORITHMS: dict[str, tuple[str, str]] = {
    "hs256": ("HMAC-SHA256", "mac"),
    "hs384": ("HMAC-SHA384", "mac"),
    "hs512": ("HMAC-SHA512", "mac"),
    "rs256": ("RSA", "asymmetric"),
    "rs384": ("RSA", "asymmetric"),
    "rs512": ("RSA", "asymmetric"),
    "ps256": ("RSA", "asymmetric"),
    "ps384": ("RSA", "asymmetric"),
    "ps512": ("RSA", "asymmetric"),
    "es256": ("ECDSA", "asymmetric"),
    "es256k": ("ECDSA", "asymmetric"),
    "es384": ("ECDSA", "asymmetric"),
    "es512": ("ECDSA", "asymmetric"),
    "eddsa": ("Ed25519", "asymmetric"),
}

EC_CURVES: dict[str, tuple[str, str]] = {
    "secp256r1": ("ECDSA-P256", "asymmetric"),
    "secp384r1": ("ECDSA-P384", "asymmetric"),
    "secp521r1": ("ECDSA-P521", "asymmetric"),
}

PYCA_CIPHER_ALGORITHMS: dict[str, tuple[str, str]] = {
    "aes": ("AES", "symmetric"),
    "tripledes": ("3DES", "symmetric"),
    "arc4": ("RC4", "symmetric"),
    "chacha20": ("ChaCha20-Poly1305", "symmetric"),
    "chacha20poly1305": ("ChaCha20-Poly1305", "symmetric"),
}

PYCRYPTODOME_CIPHERS: dict[str, tuple[str, str]] = {
    "aes": ("AES", "symmetric"),
    "des3": ("3DES", "symmetric"),
    "des": ("DES", "symmetric"),
    "arc2": ("RC2", "symmetric"),
    "arc4": ("RC4", "symmetric"),
    "arcfour": ("RC4", "symmetric"),
    "blowfish": ("Blowfish", "symmetric"),
}

RSA_KEY_SIZE_NAMES: dict[int, str] = {
    1024: "RSA-1024",
    2048: "RSA-2048",
    3072: "RSA-3072",
    4096: "RSA-4096",
}

WEAK_TLS_CIPHER_MARKERS: dict[str, tuple[str, str]] = {
    "3DES": ("3DES", "tls-cipher-suite"),
    "DES-CBC3": ("3DES", "tls-cipher-suite"),
    "RC4": ("RC4", "tls-cipher-suite"),
    "RC2": ("RC2", "tls-cipher-suite"),
    "DES": ("DES", "tls-cipher-suite"),
    "MD5": ("MD5", "tls-cipher-suite"),
}

_WEAK_TLS_MARKER_RE = re.compile(r"3DES|DES-CBC3|RC4|RC2|DES-|MD5")

try:
    import tree_sitter_javascript as _ts_javascript
    from tree_sitter import Language as _TSLanguage
    from tree_sitter import Parser as _TSParser

    _JS_LANGUAGE: Any = _TSLanguage(_ts_javascript.language())
    _TREE_SITTER_JS_OK = True
except Exception:
    _JS_LANGUAGE = None
    _TREE_SITTER_JS_OK = False

try:
    import tree_sitter_typescript as _ts_typescript

    _TS_LANGUAGE: Any = _TSLanguage(_ts_typescript.language_typescript())
    _TREE_SITTER_TS_OK = True
except Exception:
    _TS_LANGUAGE = None
    _TREE_SITTER_TS_OK = False


DETECTOR_CAPABILITIES: dict[str, str] = {
    "python": "stdlib-ast",
    "javascript": DETECTOR_TREE_SITTER if _TREE_SITTER_JS_OK else DETECTOR_REGEX_FALLBACK,
    "typescript": DETECTOR_TREE_SITTER if _TREE_SITTER_TS_OK else DETECTOR_REGEX_FALLBACK,
}
for _lang in ("go", "java", "rust", "c", "cpp", "csharp", "ruby", "php", "swift", "kotlin"):
    DETECTOR_CAPABILITIES[_lang] = DETECTOR_REGEX_FALLBACK


def is_test_path(path: Path | str) -> bool:
    p = Path(path)
    parts = {part.lower() for part in p.parts}
    name = p.name.lower()
    return (
        bool(parts & TEST_DIRECTORY_NAMES)
        or name.startswith("test_")
        or name.startswith("test.")
        or name == "conftest.py"
        or name.endswith("_test.py")
        or name.endswith("_test.js")
        or name.endswith("_test.jsx")
        or name.endswith("_test.ts")
        or name.endswith("_test.tsx")
        or ".test." in name
        or ".spec." in name
    )


class _ImportMap:
    def __init__(self) -> None:
        self.bindings: dict[str, str] = {}

    def add_import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            self.bindings[alias.asname or root] = alias.name if alias.asname else root

    def add_import_from(self, node: ast.ImportFrom) -> None:
        if node.module is None or node.level:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            full = f"{node.module}.{alias.name}"
            self.bindings[alias.asname or alias.name] = full.lower()

    def resolve(self, root_name: str) -> str | None:
        bound = self.bindings.get(root_name)
        if bound is not None:
            return bound
        lowered = root_name.lower()
        if lowered in KNOWN_CRYPTO_ROOT_MODULES:
            return lowered
        return None


def _dotted_chain(node: ast.expr, imports: _ImportMap) -> tuple[str, ...] | None:
    attrs: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        attrs.append(current.attr.lower())
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    origin = imports.resolve(current.id)
    if origin is None:
        return None
    return tuple((*origin.split("."), *reversed(attrs)))


def _endswith_suffix(chain: tuple[str, ...], suffix: tuple[str, ...]) -> bool:
    if len(suffix) > len(chain):
        return False
    return tuple(chain[-len(suffix):]) == suffix


def _const_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _arg_or_kwarg(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    if len(call.args) > index:
        return call.args[index]
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def _kwarg(call: ast.Call, keyword: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == keyword:
            return kw.value
    return None


def _evaluate_py_call(call: ast.Call, imports: _ImportMap) -> list[tuple[str, str]]:
    func = call.func
    chain: tuple[str, ...] | None
    if isinstance(func, ast.Name):
        origin = imports.resolve(func.id)
        if origin is None:
            return []
        chain = tuple(origin.split("."))
    else:
        chain = _dotted_chain(func, imports)
    if not chain:
        return []

    results: list[tuple[str, str]] = []

    if chain[0] == "hashlib":
        if len(chain) == 2 and chain[1] in PY_HASH_FUNCTIONS:
            results.append(PY_HASH_FUNCTIONS[chain[1]])
        elif chain[-1] == "new":
            name = _const_str(_arg_or_kwarg(call, 0, "name"))
            if name is not None and name.lower() in CONST_HASH_NAMES:
                results.append(CONST_HASH_NAMES[name.lower()])
        elif chain[-1] == "pbkdf2_hmac":
            name = _const_str(_arg_or_kwarg(call, 0, "hash_name"))
            mapped = CONST_HASH_NAMES.get(name.lower()) if name else None
            hmac_names = {canonical for canonical, _ in PY_HASH_FUNCTIONS.values()}
            if mapped and mapped[0] in hmac_names:
                results.append((f"HMAC-{mapped[0]}", "mac"))

    if chain[0] == "hmac" and chain[-1] == "new":
        digestmod = _positional_digestmod(call)
        algo = _resolve_digestmod(digestmod, imports)
        if algo:
            results.append(algo)

    if len(chain) >= 2 and chain[-2] == "hashes" and chain[-1] in PY_HASH_CLASSES:
        results.append(PY_HASH_CLASSES[chain[-1]])

    if len(chain) >= 3 and chain[-3:-1] == ("ciphers", "algorithms"):
        mapped = PYCA_CIPHER_ALGORITHMS.get(chain[-1])
        if mapped:
            results.append(mapped)

    if len(chain) >= 3 and chain[-3] == "cipher" and chain[-1] == "new":
        mapped = PYCRYPTODOME_CIPHERS.get(chain[-2])
        if mapped:
            results.append(mapped)

    if _endswith_suffix(chain, ("asymmetric", "rsa", "generate_private_key")):
        key_size = _const_int(_kwarg(call, "key_size"))
        if key_size is not None and key_size in RSA_KEY_SIZE_NAMES:
            results.append((RSA_KEY_SIZE_NAMES[key_size], "asymmetric"))
        else:
            results.append(("RSA", "asymmetric"))
    if _endswith_suffix(chain, ("asymmetric", "ec", "generate_private_key")) or _endswith_suffix(
        chain, ("publickey", "ecc", "generate")
    ):
        curve_node = _kwarg(call, "curve")
        while isinstance(curve_node, ast.Call):
            curve_node = curve_node.func
        curve_name = None
        if isinstance(curve_node, (ast.Attribute, ast.Name)):
            curve_name = getattr(curve_node, "attr", None) or getattr(curve_node, "id", None)
        mapped = EC_CURVES.get(curve_name.lower()) if curve_name else None
        results.append(mapped if mapped else ("ECDSA", "asymmetric"))
    for module, algo in (
        ("ed25519", "Ed25519"),
        ("ed448", "Ed448"),
        ("x25519", "X25519"),
        ("x448", "X448"),
    ):
        if "asymmetric" in chain and module in chain and chain[-1] in {"generate", "sign"}:
            results.append((algo, "asymmetric"))
    if _endswith_suffix(chain, ("asymmetric", "dsa", "generate_private_key")) or _endswith_suffix(
        chain, ("publickey", "dsa", "generate")
    ):
        results.append(("DSA", "asymmetric"))
    if _endswith_suffix(chain, ("asymmetric", "dh")) and chain[-1] in {
        "generate_parameters",
        "generate_private_key",
    }:
        results.append(("DH", "asymmetric"))
    if _endswith_suffix(chain, ("publickey", "rsa", "generate")):
        bits = _const_int(_arg_or_kwarg(call, 0, "bits"))
        if bits is not None and bits in RSA_KEY_SIZE_NAMES:
            results.append((RSA_KEY_SIZE_NAMES[bits], "asymmetric"))
        else:
            results.append(("RSA", "asymmetric"))
    if _endswith_suffix(chain, ("publickey", "ed25519", "generate")):
        results.append(("Ed25519", "asymmetric"))

    if _endswith_suffix(chain, ("jwt", "encode")) or _endswith_suffix(chain, ("jwt", "decode")):
        algos: list[str] = []
        single = _const_str(_kwarg(call, "algorithm"))
        if single is not None:
            algos.append(single)
        listed = _kwarg(call, "algorithms")
        if isinstance(listed, (ast.List, ast.Tuple)):
            for element in listed.elts:
                name = _const_str(element)
                if name is not None:
                    algos.append(name)
        for algo in algos:
            mapped = JWT_ALGORITHMS.get(algo.lower())
            if mapped:
                results.append(mapped)

    if _endswith_suffix(chain, ("ssl", "sslcontext")) or _endswith_suffix(
        chain, ("ssl", "create_default_context")
    ):
        results.append(("TLS", "protocol"))

    return _dedupe_pairs(results)


def _positional_digestmod(call: ast.Call) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == "digestmod":
            return kw.value
    if len(call.args) >= 3:
        return call.args[2]
    return None


def _resolve_digestmod(node: ast.expr | None, imports: _ImportMap) -> tuple[str, str] | None:
    if node is None:
        return None
    name = _const_str(node)
    if name is not None:
        mapped = CONST_HASH_NAMES.get(name.lower())
        if mapped and mapped[0] in PY_HASH_FUNCTIONS_INV:
            return (f"HMAC-{mapped[0]}", "mac")
        return None
    if isinstance(node, (ast.Attribute, ast.Name)):
        chain = _dotted_chain(node, imports)
        if chain and chain[0] == "hashlib" and len(chain) == 2 and chain[1] in PY_HASH_FUNCTIONS:
            return (f"HMAC-{PY_HASH_FUNCTIONS[chain[1]][0]}", "mac")
    return None


PY_HASH_FUNCTIONS_INV: set[str] = {algo for algo, _ in PY_HASH_FUNCTIONS.values()}


def _const_int(node: ast.expr | None) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _dedupe_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    ordered: list[tuple[str, str]] = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            ordered.append(pair)
    return ordered


def _scoped_nodes(tree: ast.AST) -> Iterator[tuple[ast.AST, list[str]]]:
    stack: list[str] = []

    def visit(node: ast.AST) -> Iterator[tuple[ast.AST, list[str]]]:
        entered = False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack.append(node.name)
            entered = True
        yield node, list(stack)
        for child in ast.iter_child_nodes(node):
            yield from visit(child)
        if entered:
            stack.pop()

    yield from visit(tree)


def _weak_tls_cipher_findings(call: ast.Call) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    targets = []
    weak_methods = {"set_ciphers", "set_cipher_list"}
    if isinstance(call.func, ast.Attribute) and call.func.attr in weak_methods:
        targets = list(call.args)
    for target in targets:
        value = _const_str(target)
        if value is None:
            continue
        for match in _WEAK_TLS_MARKER_RE.finditer(value):
            token = match.group(0).rstrip("-")
            mapped = WEAK_TLS_CIPHER_MARKERS.get(token)
            if mapped:
                found.append(mapped)
    return _dedupe_pairs(found)


def scan_python_source(content: str, path: Path) -> list[AssetFinding]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return _regex_fallback_findings(content, path, "python")

    lines = content.splitlines()
    in_test = is_test_path(path)
    findings: list[AssetFinding] = []
    imports = _ImportMap()

    def emit(call: ast.Call, pairs: list[tuple[str, str]], stack: list[str]) -> None:
        scope_path = ".".join(stack) if stack else "<module>"
        evidence = lines[call.lineno - 1] if call.lineno <= len(lines) else ""
        for algo, ktype in pairs:
            findings.append(
                _build_finding(
                    path=path,
                    algorithm=algo,
                    key_type=ktype,
                    line=call.lineno,
                    end_line=getattr(call, "end_lineno", None),
                    col=call.col_offset,
                    scope=scope_path,
                    function=_nearest_function(stack),
                    language="python",
                    detector=DETECTOR_PYTHON,
                    in_test=in_test,
                    evidence=evidence,
                )
            )

    for node, scope_stack in _scoped_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                imports.add_import(node)
            else:
                imports.add_import_from(node)
            continue
        if not isinstance(node, ast.Call):
            continue
        matched = _evaluate_py_call(node, imports)
        weak = _weak_tls_cipher_findings(node)
        combined = _dedupe_pairs(matched + weak)
        if combined:
            emit(node, combined, scope_stack)

    return findings


def _nearest_function(scope_stack: list[str]) -> str | None:
    return scope_stack[-1] if scope_stack else None


def _build_finding(
    path: Path,
    algorithm: str,
    key_type: str,
    line: int | None,
    end_line: int | None,
    col: int | None,
    scope: str,
    function: str | None,
    language: str,
    detector: str,
    in_test: bool,
    evidence: str,
) -> AssetFinding:
    metadata: dict[str, Any] = {
        "detector": detector,
        "language": language,
        "line": line,
        "end_lineno": end_line,
        "col": col,
        "scope": scope,
        "function": function,
        "in_test": in_test,
        "evidence": (evidence or "").strip()[:200],
    }
    return AssetFinding(
        asset_type=ASSET_TYPE,
        host=str(path),
        algorithm=algorithm,
        key_type=key_type,
        criticality="medium" if in_test else "high",
        metadata=metadata,
    )


def mask_js_source(src: str) -> str:
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            j = i
            while j < n and src[j] != "\n":
                out[j] = " "
                j += 1
            i = j
        elif ch == "/" and nxt == "*":
            end = src.find("*/", i + 2)
            stop = n if end == -1 else end + 2
            for k in range(i, stop):
                if src[k] != "\n":
                    out[k] = " "
            i = stop
        elif ch in "\"'`":
            quote = ch
            j = i + 1
            while j < n:
                c = src[j]
                if c == "\\":
                    out[j] = " "
                    if j + 1 < n:
                        out[j + 1] = " "
                    j += 2
                    continue
                if c == quote:
                    break
                if c != "\n":
                    out[j] = " "
                j += 1
            i = j + 1
        else:
            i += 1
    return "".join(out)


def extract_call_args(raw: str, open_paren_idx: int, max_len: int = 400) -> str:
    depth = 0
    in_str: str | None = None
    escaped = False
    i = open_paren_idx
    limit = min(len(raw), open_paren_idx + max_len)
    while i < limit:
        ch = raw[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in "\"'`":
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth <= 0:
                    return raw[open_paren_idx + 1 : i]
        i += 1
    return raw[open_paren_idx + 1 : limit]


def first_js_string(args: str) -> str | None:
    match = re.search(r"[\"'`]([^\"'`]*)[\"'`]", args)
    return match.group(1) if match else None


def classify_js_algo_string(value: str | None) -> tuple[str, str] | None:
    if not value:
        return None
    v = value.lower()
    if v.startswith("sha3-"):
        return ("SHA3-" + v[5:].upper(), "hash")
    direct = {
        "md5": "MD5",
        "sha1": "SHA-1",
        "sha256": "SHA-256",
        "sha384": "SHA-384",
        "sha512": "SHA-512",
    }
    if v in direct:
        return (direct[v], "hash")
    if v.startswith("aes"):
        if "-128" in v:
            return ("AES-128", "symmetric")
        if "-192" in v:
            return ("AES-192", "symmetric")
        return ("AES", "symmetric")
    if "des-ede3" in v or "des3" in v or "des-cbc3" in v:
        return ("3DES", "symmetric")
    if v.startswith("des"):
        return ("DES", "symmetric")
    if v.startswith("rc4"):
        return ("RC4", "symmetric")
    if v.startswith("chacha20"):
        return ("ChaCha20-Poly1305", "symmetric")
    subtle_map = {
        "rsa-oaep": ("RSA", "asymmetric"),
        "rsa-pss": ("RSA", "asymmetric"),
        "rsassa-pss": ("RSA", "asymmetric"),
        "rsa": ("RSA", "asymmetric"),
        "ecdsa": ("ECDSA", "asymmetric"),
        "ecdh": ("ECDH", "asymmetric"),
        "ed25519": ("Ed25519", "asymmetric"),
        "x25519": ("X25519", "asymmetric"),
        "hmac": ("HMAC-SHA256", "mac"),
    }
    return subtle_map.get(v)


def classify_js_call(callee: str, args: str) -> list[tuple[str, str]]:
    normalized = re.sub(r"\s+", "", callee).lower()
    results: list[tuple[str, str]] = []

    def add(pair: tuple[str, str] | None) -> None:
        if pair:
            results.append(pair)

    if normalized.endswith(".createhash"):
        add(classify_js_algo_string(first_js_string(args)))
    elif normalized.endswith((".createcipheriv", ".createdecipheriv", ".createcipher")):
        add(classify_js_algo_string(first_js_string(args)))
    elif normalized.endswith(".generatekeypairsync"):
        add(classify_js_algo_string(first_js_string(args)))
    elif ".subtle." in normalized and normalized.split(".")[-1] in {
        "generatekey",
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "digest",
        "importkey",
        "derivebits",
        "derivekey",
        "wrapkey",
        "unwrapkey",
    }:
        add(classify_js_algo_string(first_js_string(args)))
    elif re.fullmatch(r"(jwt|jose)\.(sign|verify|decode)", normalized):
        algo_match = re.search(
            r"algorithms?\s*:\s*(\[.*?\]|['\"][A-Za-z0-9]+['\"])",
            args,
            re.DOTALL,
        )
        if algo_match:
            quoted = re.findall(r"[\"']([A-Za-z0-9]+)[\"']", algo_match.group(1))
            for candidate in quoted:
                mapped = JWT_ALGORITHMS.get(candidate.lower())
                if mapped:
                    results.append(mapped)
                    break
    elif normalized.endswith("ethers.wallet"):
        results.append(("ECDSA", "asymmetric"))
    elif re.fullmatch(r"require|import", normalized):
        target = (first_js_string(args) or "").lower()
        if target in {"crypto", "node:crypto"}:
            results.append(("node-crypto", "library_import"))
        elif target == "jsonwebtoken":
            results.append(("jwt", "library_import"))

    return _dedupe_pairs(results)


_JS_CALLEE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"crypto\s*\.\s*createHash\b", "crypto.createHash"),
    (r"\)\s*\.\s*createHash\b", ".createHash"),
    (r"crypto\s*\.\s*createCipheriv\b", "crypto.createCipheriv"),
    (r"\)\s*\.\s*createCipheriv\b", ".createCipheriv"),
    (r"crypto\s*\.\s*createDecipheriv\b", "crypto.createDecipheriv"),
    (r"crypto\s*\.\s*createCipher\b", "crypto.createCipher"),
    (r"crypto\s*\.\s*generateKeyPairSync\b", "crypto.generateKeyPairSync"),
    (r"\)\s*\.\s*generateKeyPairSync\b", ".generateKeyPairSync"),
    (r"crypto\s*\.\s*subtle\s*\.\s*generateKey\b", "crypto.subtle.generateKey"),
    (r"crypto\s*\.\s*subtle\s*\.\s*sign\b", "crypto.subtle.sign"),
    (r"crypto\s*\.\s*subtle\s*\.\s*verify\b", "crypto.subtle.verify"),
    (r"crypto\s*\.\s*subtle\s*\.\s*encrypt\b", "crypto.subtle.encrypt"),
    (r"crypto\s*\.\s*subtle\s*\.\s*decrypt\b", "crypto.subtle.decrypt"),
    (r"crypto\s*\.\s*subtle\s*\.\s*digest\b", "crypto.subtle.digest"),
    (r"crypto\s*\.\s*subtle\s*\.\s*importKey\b", "crypto.subtle.importKey"),
    (r"crypto\s*\.\s*subtle\s*\.\s*deriveBits\b", "crypto.subtle.deriveBits"),
    (r"crypto\s*\.\s*subtle\s*\.\s*deriveKey\b", "crypto.subtle.deriveKey"),
    (r"jwt\s*\.\s*sign\b", "jwt.sign"),
    (r"jwt\s*\.\s*verify\b", "jwt.verify"),
    (r"jwt\s*\.\s*decode\b", "jwt.decode"),
    (r"(?:new\s+)?ethers\s*\.\s*Wallet\b", "ethers.Wallet"),
    (r"require\s*\(", "require"),
)


def _js_scope_at(masked: str, pos: int) -> str:
    idx = masked.rfind("function ", 0, pos)
    alt = masked.rfind("class ", 0, pos)
    if alt > idx:
        idx = alt
    if idx == -1:
        return "<module>"
    snippet = masked[idx : idx + 80]
    match = re.search(r"(?:function|class)\s+([A-Za-z_$][\w$]*)", snippet)
    return match.group(1) if match else "<module>"


def scan_javascript_fallback(content: str, path: Path) -> list[AssetFinding]:
    masked = mask_js_source(content)
    lines = content.splitlines()
    language = "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"
    in_test = is_test_path(path)
    findings: list[AssetFinding] = []
    consumed: set[tuple[int, str]] = set()

    for pattern, callee_name in _JS_CALLEE_PATTERNS:
        boundary = "" if pattern.startswith("\\)") else r"(?<![\w$.\"'`])"
        regex = re.compile(boundary + pattern)
        for match in regex.finditer(masked):
            anchor_start = match.start()
            key = (anchor_start, callee_name)
            if key in consumed:
                continue
            paren_idx = masked.find("(", match.end() - 1)
            if paren_idx == -1 or masked[paren_idx] != "(":
                continue
            args = extract_call_args(content, paren_idx)
            pairs = classify_js_call(callee_name, args)
            if not pairs:
                continue
            consumed.add(key)
            line = masked.count("\n", 0, anchor_start) + 1
            scope = _js_scope_at(masked, anchor_start)
            evidence = lines[line - 1] if line <= len(lines) else ""
            for algo, ktype in pairs:
                findings.append(
                    _build_finding(
                        path=path,
                        algorithm=algo,
                        key_type=ktype,
                        line=line,
                        end_line=None,
                        col=None,
                        scope=scope,
                        function=scope if scope != "<module>" else None,
                        language=language,
                        detector=DETECTOR_REGEX_FALLBACK,
                        in_test=in_test,
                        evidence=evidence,
                    )
                )
    return findings


def _ts_make_parser(language: Any) -> Any:
    parser = _TSParser()
    try:
        parser.language = language
    except (AttributeError, TypeError):
        parser.set_language(language)
    return parser


def _iter_ts_calls(node: Any, stack: list[str]) -> Iterator[tuple[Any, list[str]]]:
    entered = False
    if node.type in {
        "function_declaration",
        "generator_function_declaration",
        "method_definition",
        "class_declaration",
    }:
        name_node = node.child_by_field_name("name")
        name = None
        if name_node is not None and name_node.text:
            name = name_node.text.decode("utf-8", "replace")
        if name:
            stack.append(name)
            entered = True
    if node.type in {"call_expression", "new_expression"}:
        yield node, list(stack)
    for child in node.children:
        yield from _iter_ts_calls(child, stack)
    if entered:
        stack.pop()


def _scan_javascript_tree_sitter(content: str, path: Path) -> list[AssetFinding] | None:
    if not _TREE_SITTER_JS_OK or _JS_LANGUAGE is None:
        return None
    language = "typescript" if path.suffix.lower() in {".ts", ".tsx"} else "javascript"
    active_language = _JS_LANGUAGE
    if language == "typescript" and _TREE_SITTER_TS_OK and _TS_LANGUAGE is not None:
        active_language = _TS_LANGUAGE
    try:
        parser = _ts_make_parser(active_language)
    except Exception:
        return None
    try:
        tree = parser.parse(content.encode("utf-8"))
    except Exception:
        return None

    lines = content.splitlines()
    in_test = is_test_path(path)
    findings: list[AssetFinding] = []
    for node, stack in _iter_ts_calls(tree.root_node, []):
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments") or node.child_by_field_name("parameters")
        if fn is None:
            continue
        callee_text = fn.text.decode("utf-8", "replace") if fn.text else ""
        args_text = args.text.decode("utf-8", "replace") if args is not None and args.text else ""
        pairs = classify_js_call(callee_text, args_text)
        if not pairs:
            continue
        line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        scope_path = ".".join(stack) if stack else "<module>"
        evidence = lines[line - 1] if line <= len(lines) else ""
        for algo, ktype in pairs:
            findings.append(
                _build_finding(
                    path=path,
                    algorithm=algo,
                    key_type=ktype,
                    line=line,
                    end_line=end_line,
                    col=node.start_point[1],
                    scope=scope_path,
                    function=stack[-1] if stack else None,
                    language=language,
                    detector=DETECTOR_TREE_SITTER,
                    in_test=in_test,
                    evidence=evidence,
                )
            )
    return findings


def scan_javascript_source(
    content: str,
    path: Path,
    use_tree_sitter: bool = True,
) -> list[AssetFinding]:
    if use_tree_sitter:
        result = _scan_javascript_tree_sitter(content, path)
        if result is not None:
            return result
    return scan_javascript_fallback(content, path)


_REGEX_FALLBACK_LANGUAGES = {
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".cs": "csharp",
}


def _regex_fallback_findings(content: str, path: Path, language: str) -> list[AssetFinding]:
    from .source_scanner import CRYPTO_PATTERNS

    patterns = CRYPTO_PATTERNS.get(language, [])
    if not patterns:
        return []
    lines = content.splitlines()
    in_test = is_test_path(path)
    seen: set[tuple[int, str]] = set()
    findings: list[AssetFinding] = []
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
        for pattern, algorithm, key_type in patterns:
            if re.search(pattern, line):
                key = (line_num, algorithm)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    _build_finding(
                        path=path,
                        algorithm=algorithm,
                        key_type=key_type,
                        line=line_num,
                        end_line=None,
                        col=None,
                        scope="<module>",
                        function=None,
                        language=language,
                        detector=DETECTOR_REGEX_FALLBACK,
                        in_test=in_test,
                        evidence=line,
                    )
                )
    return findings


def scan_file_ast(path: Path | str, use_tree_sitter: bool = True) -> list[AssetFinding]:
    file_path = Path(path)
    suffix = file_path.suffix.lower()
    if suffix in SKIP_EXTENSIONS or not file_path.is_file():
        return []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not content:
        return []
    if suffix in PY_AST_EXTENSIONS:
        return scan_python_source(content, file_path)
    if suffix in JS_AST_EXTENSIONS:
        return scan_javascript_source(content, file_path, use_tree_sitter=use_tree_sitter)
    language = _REGEX_FALLBACK_LANGUAGES.get(suffix)
    if language is None:
        return []
    return _regex_fallback_findings(content, file_path, language)


def scan_source_directory_ast(
    directory: str | Path,
    use_tree_sitter: bool = True,
    max_file_size: int = 5_000_000,
) -> list[AssetFinding]:
    root = Path(directory)
    if not root.exists():
        return []
    known_extensions = PY_AST_EXTENSIONS | JS_AST_EXTENSIONS | set(_REGEX_FALLBACK_LANGUAGES.keys())
    findings: list[AssetFinding] = []
    for path in sorted(root.rglob("*")):
        if any(skip in path.parts for skip in SKIP_PATTERNS):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix.lower() not in known_extensions:
            continue
        try:
            if path.stat().st_size > max_file_size:
                continue
        except OSError:
            continue
        try:
            findings.extend(scan_file_ast(path, use_tree_sitter=use_tree_sitter))
        except Exception:
            continue
    return findings


def merge_findings_dedupe(
    base: list[AssetFinding],
    extra: list[AssetFinding],
) -> list[AssetFinding]:
    merged: list[AssetFinding] = []
    seen: set[tuple[str, str | None, Any]] = set()
    for finding in [*base, *extra]:
        line = finding.metadata.get("line")
        key = (finding.location, finding.algorithm, line)
        if key in seen:
            continue
        seen.add(key)
        merged.append(finding)
    return merged


def scan_with_ast(path: Path | str, content: str, language: str) -> list[AssetFinding]:
    file_path = Path(path)
    if language == "python":
        return scan_python_source(content, file_path)
    if language in {"javascript", "typescript"}:
        return scan_javascript_source(content, file_path)
    return _regex_fallback_findings(content, file_path, language)
