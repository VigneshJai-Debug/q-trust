import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { ScannerDashboard } from "@/components/scanner-dashboard";

const SCAN_RESPONSE = {
  target: "/repo",
  scanType: "source",
  timestamp: "2026-08-24T00:00:00.000Z",
  findings: [
    {
      file: "src/tls.py",
      algorithm: "RSA-2048",
      line: 12,
      severity: "critical",
      message: "quantum-vulnerable key exchange",
    },
    {
      file: "src/jwt.go",
      algorithm: "ECDSA-P256",
      line: 40,
      severity: "high",
      message: "classical signature scheme",
    },
  ],
};

const fetchMock = vi.fn();

vi.mock("@/lib/api", () => ({
  API_BASE_URL: "http://api.test",
}));

function okResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ScannerDashboard", () => {
  it("shows the scan tab by default and switches panels on tab activation", () => {
    render(<ScannerDashboard />);

    expect(screen.getByRole("tab", { name: "Scan", selected: true })).toBeInTheDocument();
    expect(screen.getByText("Cryptographic Asset Scan")).toBeInTheDocument();
    expect(screen.queryByText("Quantum Risk Scores")).not.toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Risk Scores" }), { button: 0 });

    expect(screen.getByRole("tab", { name: "Risk Scores", selected: true })).toBeInTheDocument();
    expect(screen.getByText("Quantum Risk Scores")).toBeInTheDocument();
    expect(screen.queryByText("Cryptographic Asset Scan")).not.toBeInTheDocument();

    fireEvent.mouseDown(screen.getByRole("tab", { name: "Evidence" }), { button: 0 });
    expect(screen.getByText("Evidence Record")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Evidence", selected: true })).toBeInTheDocument();
  });

  it("sends POST /v1/scan/full when Run scan is clicked and renders the results", async () => {
    fetchMock.mockResolvedValue(okResponse(SCAN_RESPONSE));
    render(<ScannerDashboard />);

    fireEvent.change(screen.getByPlaceholderText("e.g. /opt/app or ./src"), {
      target: { value: "/repo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /run scan/i }));

    await screen.findByText("Results");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://api.test/v1/scan/full");
    expect((init as RequestInit).method).toBe("POST");
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({
      target: "/repo",
      includeSource: true,
      includeManifests: true,
    });

    expect(screen.getByText("2 findings")).toBeInTheDocument();
    expect(screen.getByText("1 critical")).toBeInTheDocument();
    expect(screen.getByText("1 high")).toBeInTheDocument();
    expect(screen.getByText("RSA-2048")).toBeInTheDocument();
    expect(screen.getByText("src/tls.py")).toBeInTheDocument();
    expect(screen.getByText("quantum-vulnerable key exchange")).toBeInTheDocument();
  });

  it("shows the backend error message when the scan request fails", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "scanner offline" }), {
        status: 503,
        headers: { "Content-Type": "application/json" },
      }),
    );
    render(<ScannerDashboard />);

    fireEvent.change(screen.getByPlaceholderText("e.g. /opt/app or ./src"), {
      target: { value: "/repo" },
    });
    fireEvent.click(screen.getByRole("button", { name: /run scan/i }));

    expect(await screen.findByText("scanner offline")).toBeInTheDocument();
    expect(screen.queryByText("Results")).not.toBeInTheDocument();
  });
});
