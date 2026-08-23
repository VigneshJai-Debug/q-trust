import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Button } from "@/components/ui/button";

describe("Button", () => {
  it("renders its children as a button", () => {
    render(<Button>Run scan</Button>);
    expect(screen.getByRole("button", { name: "Run scan" })).toBeInTheDocument();
  });

  it("applies the default variant classes", () => {
    render(<Button>Primary</Button>);
    const button = screen.getByRole("button", { name: "Primary" });
    expect(button).toHaveClass("bg-qtrust-600");
    expect(button).toHaveClass("text-white");
  });

  it("applies the requested variant and size classes", () => {
    render(
      <Button variant="outline" size="sm">
        Export
      </Button>,
    );
    const button = screen.getByRole("button", { name: "Export" });
    expect(button).toHaveClass("border-slate-300");
    expect(button).toHaveClass("h-8");
    // variant class must not leak in from other variants
    expect(button.className).not.toContain("bg-qtrust-600");
  });

  it("fires onClick when clicked", () => {
    const handleClick = vi.fn();
    render(<Button onClick={handleClick}>Click me</Button>);
    fireEvent.click(screen.getByRole("button", { name: "Click me" }));
    expect(handleClick).toHaveBeenCalledOnce();
  });

  it("does not fire onClick when disabled", () => {
    const handleClick = vi.fn();
    render(
      <Button disabled onClick={handleClick}>
        Blocked
      </Button>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Blocked" }));
    expect(handleClick).not.toHaveBeenCalled();
  });
});
