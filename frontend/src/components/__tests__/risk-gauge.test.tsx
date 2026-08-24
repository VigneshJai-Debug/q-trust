import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import RiskGauge from "@/components/risk-gauge";

describe("RiskGauge", () => {
  it("renders the numeric score and its label", () => {
    render(<RiskGauge score={87} level="CRITICAL" label="Quantum risk" />);
    expect(screen.getByText("87")).toBeInTheDocument();
    expect(screen.getByText("Quantum risk")).toBeInTheDocument();
  });

  it("applies the critical severity band classes", () => {
    const { container } = render(<RiskGauge score={90} level="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(container.querySelector(".bg-red-500\\/10")).not.toBeNull();
    expect(screen.getByText("90").className).toContain("text-red-500");
  });

  it("applies the low severity band classes for low scores", () => {
    const { container } = render(<RiskGauge score={20} level="LOW" label="Low exposure" />);
    expect(container.querySelector(".bg-green-500\\/10")).not.toBeNull();
    expect(screen.getByText("20").className).toContain("text-green-500");
    expect(screen.getByText("Low exposure")).toBeInTheDocument();
  });

  it("falls back to the neutral band for NONE level", () => {
    const { container } = render(<RiskGauge score={0} level="NONE" />);
    expect(container.querySelector(".bg-gray-500\\/10")).not.toBeNull();
    expect(screen.getByText("0").className).toContain("text-gray-500");
  });
});
