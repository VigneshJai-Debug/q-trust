"""Train Q-Trust models on REAL scanned data.

Data source: the host-disjoint real CBOM corpus in ``planner/data/real_cboms/``
built by ``scripts/build_real_cboms.py`` from a live TLS scan
(``scripts/scan_hosts.py`` → ``qtrust_ai/artifacts/real_datasets/tls_scan.json``).
Every host appears in exactly one CBOM, so train/eval splits never leak hosts.

Models:
    anomaly : VAE anomaly detector on real CBOMs + injected anomalies
    gnn     : MigrationGNNv3 on synthetic graphs mixed with real CBOM graphs
    rl      : PPO agent on real-CBOM migration environments

Usage:
    python scripts/train_real_models.py --model all
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "inspector"))
sys.path.insert(0, str(REPO_ROOT / "planner"))

DATA_DIR = REPO_ROOT / "planner" / "data" / "real_cboms"


# ---------------------------------------------------------------------------
# Real-data loading / normalization
# ---------------------------------------------------------------------------

def load_real_findings(paths: list[Path]) -> list[dict]:
    """Load the host-disjoint real CBOM corpus and flatten assets into raw
    asset records (each CBOM's assets carry ``_source`` = the CBOM file)."""
    findings = []
    for path in paths:
        data = json.loads(path.read_text())
        for f in data.get("assets", []):
            f["_source"] = path.stem
            findings.append(f)
    return findings


def normalize_asset(f: dict) -> dict:
    """Map a scanner finding onto the asset schema the models expect."""
    alg_raw = (f.get("algorithm") or "").strip()
    key_size = f.get("key_size")
    a = alg_raw.lower()
    if "withrsa" in a or a.startswith("rsa"):
        algorithm = f"RSA-{key_size}" if key_size else "RSA-2048"
        key_size = key_size or 2048
    elif "ecdsa" in a:
        algorithm = "ECDSA-P256"
        key_size = key_size or 256
    elif "ed25519" in a:
        algorithm = "Ed25519"
        key_size = key_size or 256
    else:
        algorithm = alg_raw or "Unknown"
        key_size = key_size or 0

    not_after = f.get("not_after")
    days_until_expiry = 365
    expired = bool(f.get("expired"))
    if not_after:
        try:
            expiry = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            days_until_expiry = int((expiry - datetime.now(timezone.utc)).days)
            expired = expired or days_until_expiry <= 0
        except ValueError:
            pass

    issuer, subject = f.get("issuer"), f.get("subject")
    self_signed = bool(issuer and subject and issuer == subject)

    return {
        "location": f.get("host") or f.get("location") or "unknown",
        "host": f.get("host"),
        "algorithm": algorithm,
        "key_size": int(key_size),
        "criticality": f.get("criticality") or "medium",
        "expired": expired,
        "vendor": f.get("vendor"),
        "self_signed": self_signed,
        "days_until_expiry": days_until_expiry,
        "asset_type": f.get("asset_type") or "tls_certificate",
        "_source": f.get("_source"),
    }


def group_by_host(assets: list[dict]) -> list[dict]:
    """One CBOM dict per host (the natural scanning unit)."""
    by_host: dict[str, list[dict]] = {}
    for a in assets:
        by_host.setdefault(a["host"] or a["location"], []).append(a)
    return [{"schema_version": "qtrust.cbom.v1", "assets": assets_}
            for assets_ in by_host.values()]


def pack_graph_cboms(assets: list[dict], n_packs: int, seed: int = 42) -> list[dict]:
    """Pack host groups into GNN-sized CBOMs (20-100 assets) so real graphs
    match the synthetic generator's node-count distribution."""
    rng = random.Random(seed)
    hosts = list({a["host"] or a["location"] for a in assets})
    rng.shuffle(hosts)
    packs = []
    cursor = 0
    while len(packs) < n_packs:
        size = rng.randint(6, 24)          # hosts per pack
        chunk_hosts = hosts[cursor:cursor + size]
        cursor += size
        if cursor >= len(hosts):           # reshuffle and continue
            rng.shuffle(hosts)
            cursor = 0
            chunk_hosts += hosts[:max(0, size - len(chunk_hosts))]
        pack_assets = [a for h in chunk_hosts
                       for a in assets if (a["host"] or a["location"]) == h]
        if 2 <= len(pack_assets) <= 150:
            packs.append({"schema_version": "qtrust.cbom.v1", "assets": pack_assets})
    return packs


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

def inject_anomalies(cboms: list[dict], seed: int = 7) -> list[dict]:
    """Real-world attack patterns applied to real normal CBOMs."""
    rng = random.Random(seed)
    out = []

    def clone(cbom):
        return copy.deepcopy(cbom)

    # Pattern 1: weak RSA-1024 key appears (bad rollback migration)
    for cbom in cboms:
        c = clone(cbom)
        c["assets"].append({
            "location": "unknown-host.example", "algorithm": "RSA-1024",
            "key_size": 1024, "criticality": "critical", "expired": True,
            "self_signed": True, "days_until_expiry": -30, "vendor": None,
        })
        out.append(c)

    # Pattern 2: configuration drift — every key shrinks below policy
    for cbom in cboms:
        c = clone(cbom)
        for a in c["assets"]:
            a["algorithm"] = "RSA-1024"
            a["key_size"] = 1024
            a["weak_key"] = True
        out.append(c)

    # Pattern 3: renewal failure — all certs expired simultaneously
    for cbom in cboms:
        c = clone(cbom)
        for a in c["assets"]:
            a["expired"] = True
            a["days_until_expiry"] = -rng.randint(5, 90)
        out.append(c)

    return out


def train_anomaly(per_host_cboms: list[dict], epochs: int) -> None:
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector

    rng = random.Random(123)
    shuffled = per_host_cboms[:]
    rng.shuffle(shuffled)
    cut = max(1, int(len(shuffled) * 0.8))
    train_cboms, eval_normal = shuffled[:cut], shuffled[cut:]

    detector = CBOMAnomalyDetector()
    detector.train(train_cboms, epochs=epochs,
                   save_path=str(REPO_ROOT / "inspector" / "anomaly_model_real.pt"))

    anomalies = inject_anomalies(eval_normal)

    print("\nHeld-out normal CBOMs (expected: not anomalous):")
    fp = 0
    for cbom in eval_normal:
        r = detector.score_cbom(cbom)
        fp += r.is_anomalous
    print(f"  false positives: {fp}/{len(eval_normal)}")

    print("\nInjected-anomaly CBOMs (expected: flagged):")
    tp = 0
    for i, cbom in enumerate(anomalies):
        r = detector.score_cbom(cbom)
        tp += r.is_anomalous
        if i < 9:
            print(f"  pattern {i // len(eval_normal) + 1}: "
                  f"score={r.anomaly_score:.4f} flagged={r.is_anomalous}")
    print(f"\nDetection rate: {tp}/{len(anomalies)} "
          f"({tp / max(len(anomalies), 1) * 100:.0f}%), FPR {fp}/{len(eval_normal)}")


# ---------------------------------------------------------------------------
# GNN planner
# ---------------------------------------------------------------------------

def train_gnn(real_assets: list[dict], epochs: int, synthetic_graphs: int) -> None:
    sys.path.insert(0, str(REPO_ROOT / "planner"))
    from qtrust_planner.data_generator import cbom_to_dependency_graph
    from qtrust_planner.train_gpu import train_gpu

    packs = pack_graph_cboms(real_assets, n_packs=300)
    real_graphs = [cbom_to_dependency_graph(p, seed=i) for i, p in enumerate(packs)]
    print(f"Built {len(real_graphs)} real dependency graphs "
          f"(nodes/graph: min={min(g.n_assets for g in real_graphs)}, "
          f"max={max(g.n_assets for g in real_graphs)})")

    train_gpu(
        n_graphs=synthetic_graphs,
        epochs=epochs,
        model_path=str(REPO_ROOT / "planner" / "model_gpu_v3_real.pt"),
        extra_graphs=real_graphs,
    )


# ---------------------------------------------------------------------------
# RL agent
# ---------------------------------------------------------------------------

def train_rl(real_assets: list[dict], episodes: int) -> None:
    from qtrust_planner.rl_agent import MigrationEnvironment, train_agent

    packs = pack_graph_cboms(real_assets, n_packs=100, seed=99)
    print(f"Built {len(packs)} real-CBOM RL environments")

    cycle = {"i": 0}

    def env_factory():
        env = MigrationEnvironment.from_cbom(packs[cycle["i"] % len(packs)], seed=cycle["i"])
        cycle["i"] += 1
        return env

    train_agent(
        n_episodes=episodes,
        save_path=str(REPO_ROOT / "planner" / "rl_agent_real.pt"),
        env_factory=env_factory,
    )

    # Sanity: greedy rollout on a real environment
    import torch
    from qtrust_planner.rl_agent import MigrationAgent, state_to_tensors

    device = "cuda" if torch.cuda.is_available() else "cpu"
    agent = MigrationAgent(n_features=6, hidden_dim=128).to(device)
    agent.load_state_dict(torch.load(  # nosemgrep — torch.load with weights_only=True: safe deserialization
    REPO_ROOT / "planner" / "rl_agent_real.pt",
    map_location=device, weights_only=True))
    agent.eval()
    env = MigrationEnvironment.from_cbom(packs[0])
    state = env.reset()
    total_r = 0.0
    while state.available:
        x, ei = state_to_tensors(state, device)
        logits, _ = agent(x, ei)
        mask = torch.full_like(logits, float("-inf"))
        for a in state.available:
            mask[a] = 0.0
        action = int((logits + mask).argmax().item())
        state, reward, done, _ = env.step(action)
        total_r += reward
        if done:
            break
    print(f"Greedy rollout on real env #{0}: total_reward={total_r:.2f}, "
          f"migrated={sum(state.migrated)}/{state.deadline_days}d elapsed={state.elapsed_days}")


# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["anomaly", "gnn", "rl", "all"], default="all")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--gnn-synthetic-graphs", type=int, default=50_000)
    parser.add_argument("--gnn-epochs", type=int, default=60)
    parser.add_argument("--rl-episodes", type=int, default=3_000)
    args = parser.parse_args()

    paths = sorted(DATA_DIR.glob("*.json"))
    if not paths:
        raise FileNotFoundError(f"no real CBOMs found in {DATA_DIR} — run scripts/build_real_cboms.py first")
    findings = load_real_findings(paths)
    assets = [normalize_asset(f) for f in findings]
    assets = [a for a in assets if a["algorithm"] != "Unknown" or a["key_size"]]
    print(f"Loaded {len(findings)} real assets -> {len(assets)} normalized assets")

    if args.model in ("anomaly", "all"):
        print("\n=== Anomaly detector ===")
        train_anomaly(group_by_host(assets), epochs=args.epochs)
    if args.model in ("gnn", "all"):
        print("\n=== GNN planner ===")
        train_gnn(assets, epochs=args.gnn_epochs, synthetic_graphs=args.gnn_synthetic_graphs)
    if args.model in ("rl", "all"):
        print("\n=== RL agent ===")
        train_rl(assets, episodes=args.rl_episodes)


if __name__ == "__main__":
    main()
