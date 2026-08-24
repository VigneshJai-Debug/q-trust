"""Smoke tests for the side-channel analyzer (distribution-shape detector).

CPU-safe; the detector must be trained before analyze_* calls.
"""
import pytest

torch = pytest.importorskip("torch")
np = pytest.importorskip("numpy")

from qtrust_inspector.side_channel import (  # noqa: E402
    SideChannelAnalyzer,
    SideChannelDetector,
    simulate_timing_traces,
    traces_to_model_input,
)


def test_detector_construction_and_forward():
    model = SideChannelDetector(trace_length=1000)
    x = torch.randn(4, 3, 1000)
    out = model(x)
    assert out.shape == (4,)
    assert ((out >= 0) & (out <= 1)).all()


def test_detector_rejects_short_traces():
    with pytest.raises(ValueError):
        SideChannelDetector(trace_length=16)


def test_simulated_traces_normalized():
    traces = simulate_timing_traces(n_traces=500, leakage_prob=0.0, seed=42)
    assert len(traces) == 500
    assert abs(float(traces.mean())) < 0.1
    assert abs(float(traces.std()) - 1.0) < 0.2


def test_leakage_shifts_distribution_monotonically():
    def frac_abs_above(lp):
        t = simulate_timing_traces(4000, lp, seed=9)
        return float(np.mean(np.abs(t) > 0.25))

    clean = frac_abs_above(0.0)
    strong = frac_abs_above(0.6)
    assert strong > clean + 0.05


def test_model_input_channels_shape():
    t = simulate_timing_traces(3000, 0.4, seed=1)
    ch = traces_to_model_input(t, 1000)
    assert ch.shape == (3, 1000)
    assert np.all(np.diff(ch[0]) >= 0), "channel 0 must be sorted"


def test_analyze_requires_training():
    analyzer = SideChannelAnalyzer()
    with pytest.raises(RuntimeError, match="not trained"):
        analyzer.analyze_simulated(leakage_prob=0.0)


def test_train_then_analyze_verdicts(tmp_path):
    analyzer = SideChannelAnalyzer()
    analyzer.train_detector(
        n_clean=60, n_leaking=60, epochs=5,
        save_path=str(tmp_path / "sc.pt"),
    )
    clean = analyzer.analyze_simulated(leakage_prob=0.0, seed=101)
    leaky = analyzer.analyze_simulated(leakage_prob=0.8, seed=102)

    assert 0.0 <= clean.leakage_probability <= 1.0
    assert len(clean.evidence_hash) == 66
    assert clean.leakage_probability < leaky.leakage_probability
    assert clean.verdict in {"SIDE_CHANNEL_VERIFIED", "SIDE_CHANNEL_LOW_RISK"}
    assert leaky.verdict == "SIDE_CHANNEL_HIGH_RISK"
    assert clean.gpu_used == (analyzer.device.type == "cuda")


def test_checkpoint_roundtrip(tmp_path):
    path = tmp_path / "sc.pt"
    a = SideChannelAnalyzer()
    a.train_detector(n_clean=40, n_leaking=40, epochs=3, save_path=str(path))
    b = SideChannelAnalyzer(model_path=str(path))
    r = b.analyze_simulated(leakage_prob=0.7, seed=55)
    assert r.verdict == "SIDE_CHANNEL_HIGH_RISK"
    assert b.model_trained
