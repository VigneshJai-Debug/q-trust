import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import CompliancePanel from "@/components/compliance-panel";

const RULES = [
  {
    ruleId: "NIST-1",
    ruleName: "No quantum-vulnerable key exchange",
    status: "COMPLIANT" as const,
    evidence: "TLS 1.3 with X25519MLKEM768 negotiated",
    recommendation: "None required",
  },
  {
    ruleId: "NIST-2",
    ruleName: "Disallow RSA key establishment",
    status: "NON_COMPLIANT" as const,
    evidence: "RSA-2048 key exchange on port 443",
    recommendation: "Migrate to ML-KEM-768 before 2030",
  },
];

function renderPanel() {
  return render(
    <CompliancePanel
      framework="NIST SP 800-131A"
      score={50}
      totalRules={2}
      compliantCount={1}
      nonCompliantCount={1}
      partialCount={0}
      rules={RULES}
    />,
  );
}

describe("CompliancePanel", () => {
  it("renders the framework header with its score", () => {
    renderPanel();
    expect(screen.getByText("NIST SP 800-131A")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
    expect(screen.getByText("1/2 compliant")).toBeInTheDocument();
  });

  it("renders one row per framework rule with status badges", () => {
    renderPanel();
    // Mobile card fallback duplicates table rows — use getAllByText to handle both renderings
    expect(screen.getAllByText("NIST-1")[0]).toBeInTheDocument();
    expect(screen.getAllByText("NIST-2")[0]).toBeInTheDocument();
    expect(screen.getAllByText("No quantum-vulnerable key exchange")[0]).toBeInTheDocument();
    const badges = screen.getAllByText("Non-Compliant");
    expect(badges[0].className).toContain("text-red-600");
    expect(screen.getAllByText("Compliant")[0].className).toContain("text-green-600");
  });

  it("expands a rule to show its evidence and recommendation", () => {
    renderPanel();
    expect(screen.queryByText("RSA-2048 key exchange on port 443")).not.toBeInTheDocument();

    fireEvent.click(screen.getAllByRole("button", { name: "Show" })[1]);

    expect(screen.getByText("RSA-2048 key exchange on port 443")).toBeInTheDocument();
    expect(screen.getByText("Migrate to ML-KEM-768 before 2030")).toBeInTheDocument();
  });
});
