"""Anomaly detection on CBOMs using deep learning autoencoder.

Detects unusual changes in CBOMs that may indicate security incidents:
  - Sudden appearance of weak algorithms
  - Unexpected changes in key sizes
  - Configuration drift
  - Unauthorized certificate additions

Uses a variational autoencoder (VAE) trained on CBOM feature distributions.
Anomalous CBOMs have high reconstruction error.

Usage:
    from qtrust_inspector.anomaly_detector import CBOMAnomalyDetector

    detector = CBOMAnomalyDetector()
    score = detector.score_cbom(cbom_dict)
    if score > 0.8:
        print("ANOMALY DETECTED")
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import torch
import torch.nn as nn


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a CBOM."""
    anomaly_score: float  # 0 = normal, 1 = anomalous
    is_anomalous: bool
    threshold: float
    asset_count: int
    features_analyzed: int
    top_anomalous_assets: list[dict]  # assets with highest reconstruction error
    evidence_hash: str
    timestamp: str


class CBOMVariationalAutoencoder(nn.Module):
    """Variational autoencoder for CBOM anomaly detection.

    Architecture:
        Encoder: (n_features → 128 → 64 → 32) → latent (16)
        Decoder: (16 → 32 → 64 → 128 → n_features)

    Trained on normal CBOMs. Anomalous CBOMs have high reconstruction error.
    """

    def __init__(self, n_features: int = 10, latent_dim: int = 16):
        super().__init__()
        self.n_features = n_features
        self.latent_dim = latent_dim

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(n_features, 128),
            nn.ReLU(),
            nn.BatchNorm1d(128),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, 32),
            nn.ReLU(),
        )

        # Latent space
        self.fc_mu = nn.Linear(32, latent_dim)
        self.fc_logvar = nn.Linear(32, latent_dim)

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, n_features),
        )

    def encode(self, x):
        h = self.encoder(x)
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar

    def reparameterize(self, mu, logvar):
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z):
        return self.decoder(z)

    def forward(self, x):
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        recon = self.decode(z)
        return recon, mu, logvar

    def reconstruction_error(self, x):
        """Per-sample reconstruction error (lower = more normal)."""
        recon, _, _ = self.forward(x)
        error = torch.mean((recon - x) ** 2, dim=1)  # per-sample MSE
        return error


class CBOMAnomalyDetector:
    """Detect anomalies in CBOMs using a trained VAE.

    Usage:
        detector = CBOMAnomalyDetector()
        detector.train(training_cboms)  # train on normal CBOMs
        result = detector.score_cbom(new_cbom)
    """

    N_FEATURES = 10  # number of features extracted per asset

    def __init__(
        self,
        model_path: str | None = None,
        threshold: float = 0.8,
        device: str | None = None,
    ):
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.model = CBOMVariationalAutoencoder(
            n_features=self.N_FEATURES, latent_dim=16
        ).to(self.device)
        self.threshold = threshold
        self.trained = False

        if model_path:
            try:
                # nosemgrep: ts.python.pickles-in-pytorch — weights_only=True
                payload = torch.load(model_path, map_location=self.device, weights_only=True)
                if isinstance(payload, dict) and "state_dict" in payload:
                    # Checkpoint format: weights + calibrated threshold.
                    self.model.load_state_dict(payload["state_dict"])
                    saved_threshold = payload.get("threshold")
                    if isinstance(saved_threshold, (int, float)) and saved_threshold > 0:
                        self.threshold = float(saved_threshold)
                else:
                    # Legacy raw state_dict.
                    self.model.load_state_dict(payload)
                self.trained = True
                self.model.eval()
            except FileNotFoundError:
                pass

    def _extract_features(self, cbom: dict) -> torch.Tensor:
        """Extract numerical features from a CBOM for anomaly detection.

        Features per asset:
            0: algorithm_type (encoded)
            1: key_size_normalized
            2: is_pqc (0/1)
            3: criticality_score (1-4 / 4)
            4: is_expired (0/1)
            5: has_vendor (0/1)
            6: is_self_signed (0/1)
            7: rsa_key_ratio (running ratio of RSA keys)
            8: weak_key (key_size < 2048 for RSA)
            9: days_until_expiry_normalized
        """
        assets = cbom.get("assets", [])
        if not assets:
            return torch.zeros((1, self.N_FEATURES), dtype=torch.float32)

        features = []
        alg_types = {
            "RSA": 0, "ECC": 1, "DSA": 2, "DH": 3, "ECDH": 4, "ECDSA": 5,
            "EdDSA": 6, "SHA": 7, "AES": 8, "HMAC": 9, "ML-KEM": 10,
            "ML-DSA": 11, "SLH-DSA": 12, "Unknown": 13,
        }

        # Audit H-9: compute the RSA ratio once instead of re-scanning all
        # assets inside the loop (O(n²) -> O(n)).
        n_assets = len(assets)
        rsa_count = sum(1 for a in assets if "RSA" in a.get("algorithm", "").upper())
        rsa_ratio = rsa_count / n_assets

        for asset in assets:
            alg = asset.get("algorithm", "Unknown").upper()
            alg_type = 13  # Unknown
            for prefix, code in alg_types.items():
                if alg.startswith(prefix):
                    alg_type = code
                    break

            key_size = asset.get("key_size", 0)
            is_pqc = 1.0 if any(pqc in alg for pqc in ["ML-KEM", "ML-DSA", "SLH-DSA"]) else 0.0

            crit_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
            criticality = crit_map.get(asset.get("criticality", "medium"), 0.5)

            is_expired = 1.0 if asset.get("expired", False) else 0.0
            has_vendor = 1.0 if asset.get("vendor") else 0.0
            is_self_signed = 1.0 if asset.get("self_signed", False) else 0.0

            weak_key = 1.0 if ("RSA" in alg and key_size < 2048) else 0.0
            days_until_expiry = min(asset.get("days_until_expiry", 365) / 365.0, 1.0)

            features.append([
                alg_type / 13.0,
                min(key_size / 4096.0, 1.0),
                is_pqc,
                criticality,
                is_expired,
                has_vendor,
                is_self_signed,
                rsa_ratio,
                weak_key,
                days_until_expiry,
            ])

        return torch.tensor(features, dtype=torch.float32)

    def train(
        self,
        training_cboms: list[dict],
        epochs: int = 100,
        learning_rate: float = 1e-3,
        save_path: str | None = None,
    ):
        """Train the VAE on a set of normal CBOMs.

        Args:
            training_cboms: List of CBOM dicts (assumed to be "normal").
            epochs: Training epochs.
            learning_rate: Learning rate.
            save_path: If provided, save the trained model here.
        """
        # Extract features from all training CBOMs
        all_features = []
        for cbom in training_cboms:
            features = self._extract_features(cbom)
            all_features.append(features)

        if not all_features:
            raise ValueError("No features extracted from training CBOMs")

        X = torch.cat(all_features, dim=0).to(self.device)

        # Add batch dimension for BatchNorm
        if X.shape[0] < 2:
            X = X.unsqueeze(0)  # (1, n_assets, n_features) → need at least 2 for BatchNorm
            X = X.repeat(2, 1, 1)  # duplicate
            X = X.view(-1, self.N_FEATURES)

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=learning_rate)

        self.model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()

            # Forward pass
            recon, mu, logvar = self.model(X)

            # VAE loss: reconstruction + KL divergence
            recon_loss = nn.MSELoss(reduction='sum')(recon, X)
            kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + kl_div

            loss.backward()
            optimizer.step()

            if (epoch + 1) % 20 == 0:
                print(f"Epoch {epoch+1}/{epochs}: loss={loss.item():.2f}")

        self.trained = True
        self.model.eval()

        # Calibrate the decision threshold at the CBOM level: score_cbom
        # flags a CBOM when its max per-asset reconstruction error exceeds
        # the threshold, so the threshold must be the 95th percentile of
        # per-CBOM MAXIMA (using the per-asset percentile here would flag
        # nearly every multi-asset CBOM by construction).
        with torch.no_grad():
            cbom_maxima = []
            for feats in all_features:
                if feats.shape[0] == 0:
                    continue
                f = feats.to(self.device)
                cbom_maxima.append(float(self.model.reconstruction_error(f).max()))
            self.threshold = float(torch.quantile(torch.tensor(cbom_maxima), 0.95))
            print(f"Anomaly threshold set to {self.threshold:.4f} (95th pct of per-CBOM maxima)")

        if save_path:
            torch.save(
                {
                    "state_dict": self.model.state_dict(),
                    "threshold": float(self.threshold),
                },
                save_path,
            )
            print(f"Model saved to {save_path}")

    def score_cbom(self, cbom: dict) -> AnomalyResult:
        """Score a CBOM for anomaly.

        Args:
            cbom: CBOM dict to analyze.

        Returns:
            AnomalyResult with anomaly score and top anomalous assets.
        """
        features = self._extract_features(cbom)
        features = features.to(self.device)

        if not self.trained:
            raise RuntimeError(
                "anomaly detector not trained — call train() first or construct "
                "with a valid model_path"
            )

        with torch.no_grad():
            if self.device.type == "cuda":
                with torch.amp.autocast("cuda"):
                    errors = self.model.reconstruction_error(features)
            else:
                errors = self.model.reconstruction_error(features)

        # Overall anomaly score (mean reconstruction error, normalized to 0-1)
        max_error = float(errors.max())
        anomaly_score = min(max_error / (self.threshold * 2), 1.0) if self.threshold > 0 else 0.5

        # Find top anomalous assets
        assets = cbom.get("assets", [])
        top_anomalous = []
        for i, err in enumerate(errors.tolist()):
            if i < len(assets) and err > self.threshold:
                top_anomalous.append({
                    "asset_index": i,
                    "location": assets[i].get("location", "unknown"),
                    "algorithm": assets[i].get("algorithm", "unknown"),
                    "reconstruction_error": float(err),
                })

        top_anomalous.sort(key=lambda x: x["reconstruction_error"], reverse=True)

        evidence = {
            "anomaly_score": float(anomaly_score),
            "threshold": float(self.threshold),
            "asset_count": len(assets),
            "features_analyzed": self.N_FEATURES,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        evidence_hash = "0x" + hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode()
        ).hexdigest()

        return AnomalyResult(
            anomaly_score=float(anomaly_score),
            is_anomalous=bool(max_error > self.threshold),
            threshold=float(self.threshold),
            asset_count=len(assets),
            features_analyzed=self.N_FEATURES,
            top_anomalous_assets=top_anomalous[:10],
            evidence_hash=evidence_hash,
            timestamp=evidence["timestamp"],
        )

    def generate_synthetic_training_data(
        self, n_cboms: int = 1000, n_assets_per_cbom: int = 50, seed: int = 42
    ) -> list[dict]:
        """Generate synthetic normal CBOMs for training.

        Creates realistic CBOMs with typical enterprise distributions:
        ~60% RSA, ~20% ECC, ~10% Ed25519, ~10% other.
        """
        rng = np.random.default_rng(seed)
        cboms = []

        algorithms = [
            ("RSA-2048", 2048, 0.45),
            ("RSA-4096", 4096, 0.15),
            ("ECC-P256", 256, 0.15),
            ("ECC-P384", 384, 0.05),
            ("Ed25519", 256, 0.10),
            ("SHA-256", 256, 0.05),
            ("AES-256", 256, 0.05),
        ]

        for i in range(n_cboms):
            assets = []
            n = int(rng.integers(n_assets_per_cbom // 2, n_assets_per_cbom * 2))

            for j in range(n):
                alg_choice = rng.choice(
                    [a[0] for a in algorithms],
                    p=[a[2] for a in algorithms],
                )
                alg_info = next(a for a in algorithms if a[0] == alg_choice)

                assets.append({
                    "algorithm": alg_info[0],
                    "key_size": alg_info[1],
                    "criticality": rng.choice(
                        ["low", "medium", "high", "critical"], p=[0.2, 0.4, 0.3, 0.1]
                    ),
                    "expired": bool(rng.random() < 0.05),
                    "vendor": rng.choice(["DigiCert", "Let's Encrypt", "GlobalSign", None]),
                    "self_signed": bool(rng.random() < 0.1),
                    "days_until_expiry": int(rng.integers(1, 365)),
                    "location": f"host-{j}.example.com",
                })

            cboms.append({
                "assets": assets,
                "scanner_version": "synthetic-v1",
            })

        return cboms


if __name__ == "__main__":
    # Demo: train and test the anomaly detector
    detector = CBOMAnomalyDetector()

    # Generate synthetic training data
    print("Generating synthetic training data...")
    training_cboms = detector.generate_synthetic_training_data(n_cboms=500)

    # Train
    print("Training VAE...")
    detector.train(training_cboms, epochs=50, save_path="anomaly_model.pt")

    # Test on a "normal" CBOM
    print("\n--- Testing on normal CBOM ---")
    normal_cbom = training_cboms[0]
    result = detector.score_cbom(normal_cbom)
    print(f"Anomaly score: {result.anomaly_score:.4f}")
    print(f"Is anomalous: {result.is_anomalous}")

    # Test on an "anomalous" CBOM (many weak RSA keys)
    print("\n--- Testing on anomalous CBOM (many weak RSA-1024 keys) ---")
    anomalous_cbom = {
        "assets": [
            {"algorithm": "RSA-1024", "key_size": 1024, "criticality": "critical",
             "expired": True, "vendor": None, "self_signed": True,
             "days_until_expiry": 0, "location": "compromised.example.com"}
            for _ in range(20)
        ]
    }
    result = detector.score_cbom(anomalous_cbom)
    print(f"Anomaly score: {result.anomaly_score:.4f}")
    print(f"Is anomalous: {result.is_anomalous}")
    print(f"Top anomalous assets: {len(result.top_anomalous_assets)}")
