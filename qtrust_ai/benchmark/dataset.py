"""
Q-Trust PQC-Migration Benchmark — synthetic enterprise crypto datasets.

Architecture reference: ``qtrust_ai/README.md`` §28-29 (Benchmark).

Generates the Q-Trust PQC-Migration Benchmark:

    organizations × applications × crypto usages × dependency edges

Each usage sample carries the full attribute set from spec §28:

    asset, algorithm, protocol, purpose, dependency graph, business
    criticality, data sensitivity, data lifetime, vendor, hardware,
    PQC compatibility, migration cost, migration result, failure mode

Dataset discipline (§28-29) is enforced by :meth:`QTrustBenchmark.splits`:

* **Org-level splits** — every org (and its topology) lands in exactly one
  split (train / val / test / enterprise-holdout / adversarial-holdout).
  The same organization never appears in both train and test, so accuracy
  cannot be inflated by topology leakage.
* **Adversarial holdout** — adversarial orgs + the adversarial usage subset
  (obfuscated, renamed, wrappers, mixed, hidden deps …) are reserved as an
  extra holdout set ("can Q-Trust still discover crypto when the obvious
  patterns disappear?").
* **40/30/20/10 mix** — synthetic / expert-labelled / real-ish / adversarial
  provenance tags on every sample.

Target scale (README): 10k orgs × 100k apps × 1M usages × 10M edges — set via
:class:`BenchmarkConfig`. The default is CPU-friendly for tests/demos.

Example:
    from qtrust_ai.benchmark.dataset import QTrustBenchmark, BenchmarkConfig

    bench = QTrustBenchmark(BenchmarkConfig(n_orgs=50, seed=42))
    bench.generate()
    splits = bench.splits()
    assert not (set(splits["train"]["org_ids"]) & set(splits["test"]["org_ids"]))
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants — algorithm universe (anchored to NIST standards)
# ---------------------------------------------------------------------------

_ALGORITHMS: List[str] = [
    "RSA-2048", "RSA-4096", "RSA-1024", "ECDSA-P256", "ECDSA-P384",
    "ECDH-P256", "X25519", "ED25519", "DSA-2048", "DH-2048",
    "AES-128", "AES-256", "3DES", "ChaCha20-Poly1305",
    "SHA-256", "SHA-384", "SHA-512", "HMAC-SHA256", "MD5",
    "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "SLH-DSA-SHA2-128s", "HQC-128",
]

_PQC_ALGORITHMS = {"ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "SLH-DSA-SHA2-128s", "HQC-128"}

_PROTOCOLS: List[str] = ["TLS1.3", "TLS1.2", "mTLS", "SSH", "QUIC", "IPSec", "JWT", "custom"]

_PURPOSES: List[str] = [
    "key-establishment", "signature", "encryption", "hashing", "randomness", "certificate_handling",
]

_VENDORS: List[str] = ["internal", "vendorA", "vendorB", "vendorC", "openssl-ecosystem", "unknown"]

_HARDWARE: List[str] = ["x86", "arm", "hsm", "tpm", "iot-mcu", "smartcard"]

_APP_TYPES: List[str] = [
    "banking-api", "payment", "auth-service", "tls-gateway", "web", "mobile",
    "iot-firmware", "ssh", "vpn", "hsm",
]

_LIBRARIES: List[str] = ["openssl", "boringssl", "libsodium", "bouncy-castle", "mbedtls", "proprietary", "go-x-crypto"]

_CRITICALITY = ["low", "medium", "high", "critical"]

# Vendor → PQC availability (used for migration labels; vendorC stays blocked)
_VENDOR_PQC_READY: Dict[str, bool] = {
    "internal": True, "vendorA": True, "vendorB": True, "vendorC": False,
    "openssl-ecosystem": True, "unknown": False,
}

# Purpose of each algorithm family (mirrors recommender priors)
_ALGO_PURPOSE: Dict[str, str] = {
    "RSA": "signature", "ECDSA": "signature", "DSA": "signature", "ED25519": "signature",
    "ML-DSA": "signature", "SLH-DSA": "signature",
    "ECDH": "key-establishment", "X25519": "key-establishment", "DH": "key-establishment",
    "ML-KEM": "key-establishment", "HQC": "key-establishment",
    "AES": "encryption", "3DES": "encryption", "ChaCha20": "encryption",
    "SHA": "hashing", "HMAC": "hashing", "MD5": "hashing",
}


def purpose_for(algorithm: str) -> str:
    up = algorithm.upper()
    for fam, purpose in _ALGO_PURPOSE.items():
        if up.startswith(fam):
            return purpose
    return "encryption"


def is_pqc(algorithm: str) -> bool:
    return algorithm in _PQC_ALGORITHMS or any(
        p in algorithm.upper() for p in ("ML-KEM", "ML-DSA", "SLH-DSA", "HQC")
    )


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkConfig:
    """Scale + composition knobs.

    Attributes:
        n_orgs: Organizations to generate (target benchmark: 10_000).
        apps_per_org: Range ``(min, max)`` applications per org.
        usages_per_app: Range ``(min, max)`` crypto usages per app.
        edge_density: Dependency edges per usage (approx).
        adversarial_frac: Fraction of orgs generated as adversarial (≈10%).
        provenance: ``(synthetic, expert, realish, adversarial)`` mix weights.
        seed: Random seed — full dataset reproducible.
    """

    n_orgs: int = 20
    apps_per_org: Tuple[int, int] = (3, 8)
    usages_per_app: Tuple[int, int] = (2, 6)
    edge_density: float = 2.5
    adversarial_frac: float = 0.1
    provenance: Tuple[float, float, float, float] = (0.40, 0.30, 0.20, 0.10)
    seed: int = 42
    include_edges: bool = True


@dataclass
class BenchmarkUsage:
    """One crypto usage / migration unit (spec §28 sample record)."""

    usage_id: str
    org_id: str
    app_id: str
    asset: str
    algorithm: str
    protocol: str
    purpose: str
    business_criticality: str
    data_sensitivity: int
    data_lifetime_years: int
    vendor: str
    hardware: str
    library: str
    dependency_count: int
    pqc_compatible: bool
    migration_cost_hours: float
    migration_duration_days: int
    migration_result: str          # "success" | "failure" | "pending"
    failure_mode: str              # "" when success
    provenance: str                # synthetic | expert | realish | adversarial
    adversarial_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkApp:
    """Application inside an organization."""

    app_id: str
    name: str
    app_type: str
    usages: List[BenchmarkUsage] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"app_id": self.app_id, "name": self.name, "app_type": self.app_type,
                "usages": [u.to_dict() for u in self.usages]}


@dataclass
class BenchmarkOrg:
    """One organization (a topology). Never split across train/test."""

    org_id: str
    name: str
    sector: str
    apps: List[BenchmarkApp] = field(default_factory=list)
    dependency_edges: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id, "name": self.name, "sector": self.sector,
            "apps": [a.to_dict() for a in self.apps],
            "dependency_edges": self.dependency_edges,
        }

    def usage_count(self) -> int:
        return sum(len(a.usages) for a in self.apps)


# ---------------------------------------------------------------------------
# Benchmark generator
# ---------------------------------------------------------------------------

class QTrustBenchmark:
    """Q-Trust PQC-Migration Benchmark dataset generator.

    Attributes:
        config: :class:`BenchmarkConfig`.
        orgs: Generated organizations (populated by :meth:`generate`).

    Example:
        >>> bench = QTrustBenchmark(BenchmarkConfig(n_orgs=10, seed=0))
        >>> bench.generate()
        >>> bench.usage_count() > 0
        True
        >>> sp = bench.splits()
        >>> sorted(sp.keys()) == ["adversarial_holdout", "enterprise_holdout", "test", "train", "val"]
        True
    """

    def __init__(self, config: Optional[BenchmarkConfig] = None) -> None:
        self.config = config or BenchmarkConfig()
        self.orgs: List[BenchmarkOrg] = []

    # -- generation ---------------------------------------------------------

    def generate(self) -> "QTrustBenchmark":
        """Generate the full benchmark (orgs → apps → usages → edges)."""
        cfg = self.config
        rnd = random.Random(cfg.seed)
        n_adversarial = max(1, int(cfg.n_orgs * cfg.adversarial_frac))
        n_normal = cfg.n_orgs - n_adversarial
        self.orgs = []
        for i in range(n_normal):
            self.orgs.append(self._gen_org(rnd, i, adversarial=False))
        for i in range(n_adversarial):
            self.orgs.append(self._gen_org(rnd, n_normal + i, adversarial=True))
        return self

    def _gen_org(self, rnd: random.Random, idx: int, adversarial: bool) -> BenchmarkOrg:
        cfg = self.config
        org_id = f"org-{idx:05d}"
        org = BenchmarkOrg(
            org_id=org_id,
            name=f"Org {idx}",
            sector=rnd.choice(["finance", "healthcare", "government", "tech", "energy", "retail", "manufacturing"]),
        )
        n_apps = rnd.randint(*cfg.apps_per_org)
        for ai in range(n_apps):
            app = self._gen_app(rnd, org_id, ai, adversarial)
            org.apps.append(app)
        if cfg.include_edges:
            org.dependency_edges = self._gen_edges(rnd, org)
        return org

    def _gen_app(self, rnd: random.Random, org_id: str, ai: int, adversarial: bool) -> BenchmarkApp:
        app_id = f"{org_id}:app-{ai:03d}"
        app = BenchmarkApp(app_id=app_id, name=f"app-{ai}", app_type=rnd.choice(_APP_TYPES))
        n_usages = rnd.randint(*self.config.usages_per_app)
        for ui in range(n_usages):
            usage = self._gen_usage(rnd, app, ui, adversarial)
            app.usages.append(usage)
        return app

    def _gen_usage(self, rnd: random.Random, app: BenchmarkApp, ui: int, adversarial: bool) -> BenchmarkUsage:
        cfg = self.config
        # Provenance draw: adversarial orgs are the 10% adversarial mix; normal
        # orgs draw from synthetic / expert / realish (40/30/20 normalized).
        # This keeps the documented 40/30/20/10 dataset composition without
        # tagging *orgs* as adversarial (which would poison the holdout logic).
        if adversarial:
            provenance = "adversarial"
        else:
            normal = ("synthetic", "expert", "realish")
            weights = cfg.provenance[:3]
            total = sum(weights)
            prov_pick = rnd.random() * total
            cum = 0.0
            provenance = "synthetic"
            for prov, weight in zip(normal, weights):
                cum += weight
                if prov_pick <= cum:
                    provenance = prov
                    break

        if adversarial:
            algorithm = rnd.choice([a for a in _ALGORITHMS])
            # adversarial orgs skew toward obfuscated/hidden cases
            adv_type = rnd.choice(_ADVERSARIAL_TYPES)
            asset = _adv_asset_name(rnd, adv_type)
        else:
            algorithm = rnd.choice(_ALGORITHMS)
            adv_type = ""
            asset = f"{app.name}-asset-{ui:03d}"

        pqc_ready = is_pqc(algorithm)
        vendor = rnd.choice(_VENDORS)
        vendor_blocked = not _VENDOR_PQC_READY.get(vendor, True)
        criticality = rnd.choice(_CRITICALITY)
        deps = rnd.randint(0, 40) + (12 if adversarial and adv_type in ("hidden-dependencies", "conflicting-evidence") else 0)

        # Labels — deterministic heuristics anchored to the migration spec
        cost_hours, duration_days, result, failure_mode = self._label_migration(
            algorithm, vendor, criticality, deps, app.app_type, vendor_blocked,
        )

        return BenchmarkUsage(
            usage_id=f"{app.app_id}:usage-{ui:03d}",
            org_id=app.app_id.split(":")[0],
            app_id=app.app_id,
            asset=asset,
            algorithm=algorithm,
            protocol=rnd.choice(_PROTOCOLS),
            purpose=purpose_for(algorithm),
            business_criticality=criticality,
            data_sensitivity=rnd.randint(1, 5),
            data_lifetime_years=rnd.choice([1, 2, 5, 7, 10, 15, 20]),
            vendor=vendor,
            hardware=rnd.choice(_HARDWARE),
            library=rnd.choice(_LIBRARIES),
            dependency_count=deps,
            pqc_compatible=pqc_ready,
            migration_cost_hours=round(cost_hours, 1),
            migration_duration_days=duration_days,
            migration_result=result,
            failure_mode=failure_mode,
            provenance=provenance,
            adversarial_type=adv_type,
        )

    def _label_migration(
        self,
        algorithm: str,
        vendor: str,
        criticality: str,
        deps: int,
        app_type: str,
        vendor_blocked: bool,
    ) -> Tuple[float, int, str, str]:
        """Deterministic migration labels (anchored to spec §7/§8 examples).

        Cost anchors: banking-api hybrid → 84h / 12d. Failure probability is a
        small logistic over the same signals used by the failure predictor.
        """
        up = algorithm.upper()
        legacy = any(p in up for p in ("RSA", "ECDSA", "DSA", "DH", "3DES", "MD5", "AES-128")) and not vendor_blocked
        app_mult = {"banking-api": 1.0, "payment": 0.95, "iot-firmware": 1.3, "hsm": 1.2,
                    "tls-gateway": 0.7, "web": 0.55, "mobile": 0.6}.get(app_type, 0.8)
        crit_mult = {"low": 0.8, "medium": 1.0, "high": 1.15, "critical": 1.3}[criticality]
        dep_factor = 1.0 + max(0, deps - 5) * 0.03
        base = 84.0 if (legacy and app_type in ("banking-api", "payment")) else 36.0
        cost = base * app_mult * crit_mult * dep_factor * (1.35 if vendor_blocked else 1.0)
        duration = max(2, round(cost / 8))

        # Failure probability: blocked vendor + legacy + many deps → risky
        logit = -2.2 + (1.6 if vendor_blocked else 0.0) + (1.0 if legacy else 0.0) \
            + min(1.2, deps * 0.03) + (0.5 if criticality in ("high", "critical") else 0.0)
        prob = 1.0 / (1.0 + (2.71828 ** -max(-6, min(6, logit))))
        if vendor_blocked and not is_pqc(algorithm):
            result, mode = "failure", "vendor PQC unsupported"
        elif prob > 0.55:
            result, mode = "failure", "legacy client incompatibility"
        elif prob > 0.40:
            result, mode = "failure", "certificate chain issue"
        elif is_pqc(algorithm):
            result, mode = "success", ""
        else:
            result, mode = "success", ""
        return cost, duration, result, mode

    def _gen_edges(self, rnd: random.Random, org: BenchmarkOrg) -> List[Dict[str, str]]:
        """Application → library → primitive dependency edges within the org."""
        edges: List[Dict[str, str]] = []
        usage_ids = [u.usage_id for app in org.apps for u in app.usages]
        if not usage_ids:
            return edges
        for usage_id in usage_ids:
            for _ in range(max(1, int(self.config.edge_density))):
                target = rnd.choice(usage_ids)
                if target != usage_id:
                    edges.append({"src": usage_id, "dst": target, "relation": "depends_on"})
        return edges

    # -- queries ------------------------------------------------------------

    def usage_count(self) -> int:
        return sum(o.usage_count() for o in self.orgs)

    def edge_count(self) -> int:
        return sum(len(o.dependency_edges) for o in self.orgs)

    def to_records(self) -> List[Dict[str, Any]]:
        """Flat list of usage records (one row per sample, §28 fields)."""
        return [u.to_dict() for o in self.orgs for a in o.apps for u in a.usages]

    def to_json(self, path: str, indent: int = 2) -> None:
        """Export the full benchmark (orgs + edges) to JSON."""
        payload = {
            "config": asdict(self.config),
            "orgs": [o.to_dict() for o in self.orgs],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=indent)

    # -- splits (org-level, no leakage) --------------------------------------

    def _org_bucket(self, org_id: str) -> int:
        h = hashlib.sha256(org_id.encode()).hexdigest()
        return int(h[:4], 16) % 100

    def splits(
        self,
        train_frac: float = 0.60,
        val_frac: float = 0.10,
        test_frac: float = 0.15,
        enterprise_holdout_frac: float = 0.10,
    ) -> Dict[str, Dict[str, Any]]:
        """Org-level train / val / test / holdout splits — no leakage.

        Every org lands in exactly one split, keyed by a stable hash of the
        org id. Adversarial orgs are forced into ``adversarial_holdout``.

        Args:
            train_frac / val_frac / test_frac / enterprise_holdout_frac:
                Bucket fractions (must sum ≤ 1; remainder → adversarial_holdout).

        Returns:
            Dict with keys ``train``, ``val``, ``test``, ``enterprise_holdout``,
            ``adversarial_holdout``, each ``{"org_ids": [...], "records": [...]}``.
        """
        buckets: Dict[str, List[BenchmarkOrg]] = {
            "train": [], "val": [], "test": [], "enterprise_holdout": [], "adversarial_holdout": [],
        }
        for org in self.orgs:
            is_adv = any(u.adversarial_type or u.provenance == "adversarial" for a in org.apps for u in a.usages)
            if is_adv:
                buckets["adversarial_holdout"].append(org)
                continue
            b = self._org_bucket(org.org_id)
            if b < train_frac * 100:
                buckets["train"].append(org)
            elif b < (train_frac + val_frac) * 100:
                buckets["val"].append(org)
            elif b < (train_frac + val_frac + test_frac) * 100:
                buckets["test"].append(org)
            elif b < (train_frac + val_frac + test_frac + enterprise_holdout_frac) * 100:
                buckets["enterprise_holdout"].append(org)
            else:
                buckets["adversarial_holdout"].append(org)  # remainder — novel topologies

        result: Dict[str, Dict[str, Any]] = {}
        for name, orgs in buckets.items():
            result[name] = {
                "org_ids": [o.org_id for o in orgs],
                "records": [u.to_dict() for o in orgs for a in o.apps for u in a.usages],
            }
        return result

    # -- evaluation ----------------------------------------------------------

    def evaluate(self, dataset: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Self-check: no org leakage across splits + provenance mix sanity."""
        sp = self.splits()
        org_sets = {name: set(sp[name]["org_ids"]) for name in sp}
        leak = 0
        names = list(org_sets)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                leak += len(org_sets[a] & org_sets[b])
        prov = {}
        for rec in self.to_records():
            prov[rec["provenance"]] = prov.get(rec["provenance"], 0) + 1
        return {
            "orgs": len(self.orgs),
            "usages": self.usage_count(),
            "edges": self.edge_count(),
            "cross_split_org_leakage": leak,
            "provenance_mix": prov,
            "split_sizes": {k: len(v["records"]) for k, v in sp.items()},
        }


# ---------------------------------------------------------------------------
# Adversarial helpers (shared with qtrust_ai.benchmark.adversarial)
# ---------------------------------------------------------------------------

_ADVERSARIAL_TYPES: List[str] = [
    "obfuscated-crypto", "renamed-functions", "custom-wrappers", "dead-code",
    "generated-code", "mixed-algorithms", "false-positives", "hidden-dependencies",
    "unknown-vendors", "incomplete-inventories", "conflicting-evidence",
]


def _adv_asset_name(rnd: random.Random, adv_type: str) -> str:
    """Obfuscated/renamed asset names so deterministic signature rules fail."""
    if adv_type == "obfuscated-crypto":
        return "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
    if adv_type == "renamed-functions":
        return f"fn_{rnd.choice(['kdfx', 'wrap_enc', 'cipher2', 'digest_v3', 'secure_io'])}"
    if adv_type == "custom-wrappers":
        return f"cryptoWrapper{rnd.randint(1, 99)}"
    if adv_type == "generated-code":
        return f"gen_{rnd.randint(1000, 9999)}_impl"
    return f"{adv_type}-{rnd.randint(0, 999)}"


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== QTrustBenchmark demo — PQC-Migration Benchmark (§28-29) ===\n")
    bench = QTrustBenchmark(BenchmarkConfig(n_orgs=60, seed=42))
    bench.generate()
    stats = bench.evaluate()
    print(json.dumps(stats, indent=2))
    assert stats["cross_split_org_leakage"] == 0, "org leakage across splits!"

    sp = bench.splits()
    print(f"\nsplit record counts: { {k: len(v['records']) for k, v in sp.items()} }")
    print(f"split org counts:    { {k: len(v['org_ids']) for k, v in sp.items()} }")

    # Sample record (spec §28 fields)
    recs = bench.to_records()
    sample = next(r for r in recs if r["provenance"] != "adversarial")
    print("\nsample record:")
    print(json.dumps(sample, indent=2))
    assert set(sample) >= {
        "asset", "algorithm", "protocol", "purpose", "business_criticality",
        "data_sensitivity", "data_lifetime_years", "vendor", "hardware",
        "pqc_compatible", "migration_cost_hours", "migration_result", "failure_mode",
    }
    print("\n✓ sample carries all §28 attributes; org-level no-leakage splits passed")
