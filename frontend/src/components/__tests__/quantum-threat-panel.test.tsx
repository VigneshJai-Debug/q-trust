import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import QuantumThreatPanel from "@/components/quantum-threat-panel";

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

describe("QuantumThreatPanel", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders key size selector and defaults to RSA-2048", async () => {
    const fetchMock = mockFetch(200, {
      rsa_key_size: 2048,
      logical_qubits_needed: 4099,
      physical_qubits_needed: 4_099_000,
      estimated_breakable_year: null,
      based_on: "Gidney & Ekerå 2019",
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<QuantumThreatPanel />);
    fireEvent.click(screen.getByRole("button", { name: "Estimate RSA-2048 threat" }));
    await waitFor(() => expect(screen.getByText("Not before 2033")).toBeInTheDocument());
    expect(screen.getByText("4,099")).toBeInTheDocument();
  });

  it("shows CRITICAL urgency for near-term breakable keys", async () => {
    vi.stubGlobal(
      "fetch",
      mockFetch(200, {
        rsa_key_size: 1024,
        logical_qubits_needed: 2051,
        physical_qubits_needed: 2_051_000,
        estimated_breakable_year: 2027,
        based_on: "roadmaps",
      }),
    );
    render(<QuantumThreatPanel />);
    fireEvent.click(screen.getByRole("button", { name: "1024" }));
    fireEvent.click(screen.getByRole("button", { name: "Estimate RSA-1024 threat" }));
    await waitFor(() => expect(screen.getByText("CRITICAL")).toBeInTheDocument());
    expect(screen.getByText(/~2027/)).toBeInTheDocument();
  });
});
