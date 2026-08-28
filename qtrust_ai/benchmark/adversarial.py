"""
Adversarial cases — stress-test discovery models where obvious patterns vanish.

Architecture reference: ``qtrust_ai/README.md`` §29 (Adversarial training).

Generates the hard cases competitors overlook:

    obfuscated crypto, renamed functions, custom crypto wrappers, dead code,
    generated code, mixed algorithms, false positives, hidden dependencies,
    unknown vendors, incomplete inventories, conflicting evidence

Each case carries the adversarial category (``adversarial_type``) plus the
discovery difficulty properties:

* ``obfuscation`` — 0-1 how much the obvious pattern (``RSA(...)``) is hidden.
* ``renamed`` — whether the crypto API is renamed / wrapped.
* ``indirect_call`` — crypto reachable only through indirect / dynamic calls.
* ``generated`` — whether the code is machine-generated.
* ``is_crypto`` — ground-truth label (false positives are *not* crypto).

The benchmark's adversarial holdout (``dataset.py``) is built from these
cases, so evaluation answers: *"Can Q-Trust still discover cryptography when
the obvious patterns disappear?"*

Example:
    from qtrust_ai.benchmark.adversarial import AdversarialCaseGenerator

    gen = AdversarialCaseGenerator(seed=42)
    cases = gen.generate(n=50)
    assert any(c["adversarial_type"] == "obfuscated-crypto" for c in cases)
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Category catalogue (§29) — each maps to generation behavior + difficulty
ADVERSARIAL_TYPES: List[str] = [
    "obfuscated-crypto",
    "renamed-functions",
    "custom-wrappers",
    "dead-code",
    "generated-code",
    "mixed-algorithms",
    "false-positives",
    "hidden-dependencies",
    "unknown-vendors",
    "incomplete-inventories",
    "conflicting-evidence",
]

_CATEGORY_DIFFICULTY: Dict[str, float] = {
    "obfuscated-crypto": 0.85,
    "renamed-functions": 0.80,
    "custom-wrappers": 0.75,
    "dead-code": 0.35,
    "generated-code": 0.50,
    "mixed-algorithms": 0.60,
    "false-positives": 0.65,
    "hidden-dependencies": 0.90,
    "unknown-vendors": 0.70,
    "incomplete-inventories": 0.55,
    "conflicting-evidence": 0.80,
}

_ALGO_SNIPPETS = {
    "RSA-2048": ["RSA.encrypt(data)", "rsa.newkeys(2048)", "key = RSA.generate(2048)"],
    "ECDSA-P256": ["ecdsa_sign(payload)", "sign(data, P256)", "crypto.sign.SigningKey.from_pem"],
    "ECDH-P256": ["ecdh.derive(peer_pub)", "X25519(private).shared_key(peer)"],
    "AES-256": ["AES.new(key, AES.MODE_GCM)", "encrypt_aes256(plaintext)", "Fernet(key).encrypt"],
    "SHA-256": ["hashlib.sha256(data)", "SHA256(data).digest()", "digest(data)"],
    "ML-KEM-768": ["ml_kem.encaps(pub)", "kdf_encaps(pk)"],
}


def _normalized(name: str) -> str:
    return name.strip().lower().replace("_", "-").replace(" ", "-")


@dataclass
class AdversarialCase:
    """One adversarial discovery case.

    Attributes:
        case_id: Stable id.
        adversarial_type: Category from :data:`ADVERSARIAL_TYPES`.
        snippet: Code / inventory snippet for the detector.
        is_crypto: Ground truth (``False`` for false-positives).
        algorithm: Best-known algorithm (may be hidden / unknown).
        difficulty: 0-1 (how hard is this for rule-based discovery).
        properties: ``obfuscation`` / ``renamed`` / ``indirect_call`` /
            ``generated`` / ``hidden_dependency`` flags.
        description: Human explanation of the trick.
    """

    case_id: str
    adversarial_type: str
    snippet: str
    is_crypto: bool
    algorithm: str
    difficulty: float
    properties: Dict[str, bool] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdversarialCaseGenerator:
    """Generate adversarial discovery cases across all §29 categories.

    Attributes:
        seed: Deterministic generation seed.

    Example:
        >>> gen = AdversarialCaseGenerator(seed=0)
        >>> cases = gen.generate(n=10)
        >>> len(cases) == 10
        True
        >>> all(c.is_crypto or c.adversarial_type == "false-positives" for c in cases)
        True
    """

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed

    def generate(self, n: int = 100, categories: Optional[List[str]] = None) -> List[AdversarialCase]:
        """Generate *n* adversarial cases across categories (round-robin)."""
        cats = categories or ADVERSARIAL_TYPES
        rnd = random.Random(self.seed)
        cases: List[AdversarialCase] = []
        for i in range(n):
            cat = cats[i % len(cats)]
            cases.append(self._gen_case(rnd, i, cat))
        return cases

    def generate_per_category(self, per_category: int = 5) -> Dict[str, List[AdversarialCase]]:
        """Generate *per_category* cases for every category."""
        return {cat: self.generate(per_category, categories=[cat]) for cat in ADVERSARIAL_TYPES}

    # -- per-category generators --------------------------------------------

    def _gen_case(self, rnd: random.Random, idx: int, cat: str) -> AdversarialCase:
        algo = rnd.choice(list(_ALGO_SNIPPETS.keys()))
        snippet = rnd.choice(_ALGO_SNIPPETS[algo])
        diff = _CATEGORY_DIFFICULTY.get(cat, 0.5) + rnd.uniform(-0.05, 0.05)
        diff = max(0.1, min(0.98, diff))
        props: Dict[str, bool] = {
            "obfuscation": False, "renamed": False, "indirect_call": False,
            "generated": False, "hidden_dependency": False, "mixed": False,
        }
        is_crypto = True
        description = cat

        if cat == "obfuscated-crypto":
            snippet = _obfuscate(snippet, rnd)
            props["obfuscation"] = True
            description = "crypto hidden behind string encoding / control-flow flattening"
        elif cat == "renamed-functions":
            snippet = snippet.replace("RSA.encrypt", "kdfx.encrypt").replace("sha256", "digest_v3")
            props["renamed"] = True
            description = "standard crypto API renamed to project-specific names"
        elif cat == "custom-wrappers":
            snippet = f"class SecureIO:\n    def __init__(self): self._impl = {snippet!r}\n    def run(self, d): return _impl(d)"
            props["renamed"] = True
            description = "crypto wrapped in a custom abstraction layer"
        elif cat == "dead-code":
            snippet = f"if False:\n    {snippet}\nreturn data"
            description = "crypto unreachable (dead code) — detector must not flag as live risk"
        elif cat == "generated-code":
            snippet = f"// generated by schema-{rnd.randint(1, 99)}.gen\n{_obfuscate(snippet, rnd)}"
            props["generated"] = True
            description = "machine-generated code with non-idiomatic crypto"
        elif cat == "mixed-algorithms":
            snippet = f"{snippet}\n# also: {_obfuscate(_ALGO_SNIPPETS['AES-256'][0], rnd)}\n{_ALGO_SNIPPETS['SHA-256'][0]}"
            props["mixed"] = True
            description = "multiple algorithms mixed in one file — classifier must pick the risky one"
        elif cat == "false-positives":
            snippet = "import hashlib  # hash used only for cache keys, not crypto\ncache_key = hashlib.md5(str(obj)).hexdigest()"
            is_crypto = False
            algo = "MD5"
            description = "looks like crypto but is a non-security use (false positive trap)"
        elif cat == "hidden-dependencies":
            snippet = f"import {_obfuscate('libcrypto_x', rnd)}\nresult = proxy_call('{algo}', data)"
            props["hidden_dependency"] = True
            description = "crypto reachable only through a hidden / dynamic dependency"
        elif cat == "unknown-vendors":
            snippet = f"vendor = '{rnd.choice(['acme', 'globex', 'initech', 'umbrella'])}-crypto-sdk'\n{snippet}"
            description = "unrecognised vendor SDK wrapping known crypto"
        elif cat == "incomplete-inventories":
            snippet = f"{snippet}\n# missing: key material / cert chain not inventoried"
            props["hidden_dependency"] = True
            description = "partial inventory — algorithm present but dependencies unknown"
        elif cat == "conflicting-evidence":
            snippet = f"{snippet}\nassert is_deprecated('{algo}') is False  # contradicts NIST deprecation"
            description = "code comments assert safety contradicting the algorithm's status"

        case_id = "adv-" + hashlib.sha256(f"{self.seed}:{idx}:{cat}".encode()).hexdigest()[:10]
        return AdversarialCase(
            case_id=case_id, adversarial_type=cat, snippet=snippet,
            is_crypto=is_crypto, algorithm=algo, difficulty=round(float(diff), 3),
            properties=props, description=description,
        )

    # -- evaluation ----------------------------------------------------------

    def evaluate(self, cases: Optional[List[AdversarialCase]] = None) -> Dict[str, Any]:
        """Distribution stats over the generated case set."""
        cases = cases or self.generate(n=100)
        by_cat: Dict[str, int] = {}
        for c in cases:
            by_cat[c.adversarial_type] = by_cat.get(c.adversarial_type, 0) + 1
        return {
            "cases": len(cases),
            "by_category": by_cat,
            "mean_difficulty": round(sum(c.difficulty for c in cases) / len(cases), 3) if cases else 0.0,
            "false_positives": sum(1 for c in cases if not c.is_crypto),
        }


def _obfuscate(snippet: str, rnd: random.Random) -> str:
    """Simple deterministic-ish obfuscation (hex-encoding + indirect calls)."""
    enc = snippet.encode("utf-8").hex()
    return (
        f"def _d(s): return bytes.fromhex(s).decode()\n"
        f"code = '{enc}'\n"
        f"exec(_d(code))  # indirect call\n"
        f"# {''.join(rnd.choice('##//**') for _ in range(8))}"
    )


if __name__ == "__main__":
    print("=== AdversarialCaseGenerator demo — can Q-Trust still discover? (§29) ===\n")
    gen = AdversarialCaseGenerator(seed=42)
    cases = gen.generate(n=33)
    stats = gen.evaluate(cases)
    print(json.dumps(stats, indent=2))
    for c in cases[:5]:
        print(f"\n[{c.adversarial_type:22s}] difficulty={c.difficulty:.2f} is_crypto={c.is_crypto} algo={c.algorithm}")
        print(f"  {c.description}")
        print(f"  snippet: {c.snippet[:90]}...")
    assert len(cases) == 33
    assert all(c.case_id.startswith("adv-") for c in cases)
    print("\n✓ adversarial generator produced all §29 categories")
