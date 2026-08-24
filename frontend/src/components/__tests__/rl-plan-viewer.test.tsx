import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import RLPlanViewer from "@/components/rl-plan-viewer";

function mockFetch(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  });
}

describe("RLPlanViewer", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the migration order returned by the planner", async () => {
    const fetchMock = mockFetch(200, {
      method: "rl_policy",
      migration_order: [
        { asset_id: 0, algorithm: "RSA-2048" },
        { asset_id: 2, algorithm: "ECC-P256" },
        { asset_id: 4, algorithm: "RSA-2048" },
      ],
    });
    vi.stubGlobal("fetch", fetchMock);
    render(<RLPlanViewer />);
    fireEvent.click(screen.getByRole("button", { name: "Generate migration plan" }));
    await waitFor(() =>
      expect(screen.getByText("rl_policy")).toBeInTheDocument(),
    );
    expect(screen.getByText(/3 steps/)).toBeInTheDocument();
    const payload = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(payload.cbom.assets).toHaveLength(5);
  });

  it("hints at starting the planner microservice on 503", async () => {
    vi.stubGlobal("fetch", mockFetch(503, { error: "rl_planner_unavailable" }));
    render(<RLPlanViewer />);
    fireEvent.click(screen.getByRole("button", { name: "Generate migration plan" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "planner microservice unreachable",
      ),
    );
  });

  it("rejects invalid JSON without a network call", async () => {
    const fetchMock = mockFetch(200, {});
    vi.stubGlobal("fetch", fetchMock);
    render(<RLPlanViewer />);
    fireEvent.change(screen.getByLabelText("CBOM JSON for planning"), {
      target: { value: "{not json" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate migration plan" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain("not valid JSON"),
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
