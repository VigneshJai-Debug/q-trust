import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import AnomalyPanel from "@/components/anomaly-panel";

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

describe("AnomalyPanel", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("scores the demo CBOM and shows a normal verdict", async () => {
    const fetchMock = mockFetch(200, {
      anomaly_score: 0.31,
      is_anomalous: false,
      threshold: 0.28,
      asset_count: 3,
      top_anomalous_assets: [],
      evidence_hash: "0x" + "cd".repeat(32),
      timestamp: "2026-08-25T00:00:00Z",
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<AnomalyPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Score CBOM" }));
    await waitFor(() => expect(screen.getByText("Normal")).toBeInTheDocument());
    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.cbom.assets).toHaveLength(3);
  });

  it("flags anomalies and lists top assets", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(200, {
        anomaly_score: 0.75,
        is_anomalous: true,
        threshold: 0.28,
        asset_count: 1,
        top_anomalous_assets: [
          { asset_index: 0, location: "legacy.example.com", algorithm: "RSA-1024", reconstruction_error: 0.41 },
        ],
        evidence_hash: "0x" + "ef".repeat(32),
        timestamp: "2026-08-25T00:00:00Z",
      }),
    );
    render(<AnomalyPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Score CBOM" }));
    await waitFor(() =>
      expect(screen.getByText("ANOMALY DETECTED")).toBeInTheDocument(),
    );
    expect(screen.getByText(/legacy\.example\.com/)).toBeInTheDocument();
  });

  it("surfaces the training hint on 409", async () => {
    vi.stubGlobal("fetch", mockFetch(409, { error: "anomaly_detector_untrained" }));
    render(<AnomalyPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Score CBOM" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "Detector not trained yet",
      ),
    );
  });
});
