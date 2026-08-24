import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SideChannelPanel from "@/components/side-channel-panel";

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

const OK_RESULT = {
  implementation: "simulated",
  traces_collected: 10000,
  leakage_probability: 0.05,
  verdict: "SIDE_CHANNEL_VERIFIED",
  evidence_hash: "0x" + "ab".repeat(32),
  timestamp: "2026-08-24T00:00:00Z",
  gpu_used: true,
};

describe("SideChannelPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders header and demo controls", () => {
    render(<SideChannelPanel />);
    expect(screen.getByText("PQC Side-Channel Analysis")).toBeInTheDocument();
    expect(screen.getByText("GPU-accelerated")).toBeInTheDocument();
    expect(
      screen.getByRole("slider", { name: "Injected leakage probability" }),
    ).toBeInTheDocument();
  });

  it("runs a simulated analysis and shows a verified verdict", async () => {
    const fetchMock = mockFetch(200, OK_RESULT);
    vi.stubGlobal("fetch", fetchMock);

    render(<SideChannelPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Run analysis" }));

    await waitFor(() =>
      expect(screen.getByText("Side-Channel Verified")).toBeInTheDocument(),
    );
    expect(screen.getByText("5.0%")).toBeInTheDocument();
    expect(screen.getByText("10,000")).toBeInTheDocument();
    expect(screen.getByText("NVIDIA GPU")).toBeInTheDocument();

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain("/v1/gpu/side-channel/analyze");
    const payload = JSON.parse(init.body);
    expect(payload.simulated).toBe(true);
    expect(payload.leakage_prob).toBe(0);
  });

  it("shows a training hint on 409 untrained-detector errors", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(409, { error: "side_channel_detector_untrained" }),
    );

    render(<SideChannelPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Run analysis" }));

    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "Detector not trained yet",
      ),
    );
  });

  it("switches to real-binary mode and sends the command array", async () => {
    const fetchMock = mockFetch(200, { ...OK_RESULT, implementation: "./ml_dsa_sign input.hex", gpu_used: false });
    vi.stubGlobal("fetch", fetchMock);

    render(<SideChannelPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Real binary" }));
    const input = screen.getByLabelText("Implementation command");
    fireEvent.change(input, { target: { value: "./ml_dsa_sign input.hex" } });
    fireEvent.click(screen.getByRole("button", { name: "Run analysis" }));

    await waitFor(() =>
      expect(screen.getByText("./ml_dsa_sign input.hex")).toBeInTheDocument(),
    );
    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.simulated).toBe(false);
    expect(payload.implementation_cmd).toEqual(["./ml_dsa_sign", "input.hex"]);
    expect(screen.getByText("CPU")).toBeInTheDocument();
  });
});
