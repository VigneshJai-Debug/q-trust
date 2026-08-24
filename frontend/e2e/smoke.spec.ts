import { test, expect, type ConsoleMessage } from "@playwright/test";

test("home page renders the Q-Trust heading with no console errors", async ({ page }) => {
  const consoleErrors: string[] = [];
  page.on("console", (message: ConsoleMessage) => {
    if (message.type() === "error") {
      consoleErrors.push(message.text());
    }
  });

  await page.goto("/");

  const heading = page.getByRole("heading", { level: 1 });
  await expect(heading).toBeVisible();
  await expect(heading).toContainText("Q-Trust");

  const dashboardLink = page.getByRole("link", { name: "Organization dashboard" });
  const vendorsLink = page.getByRole("link", { name: "Vendor portal" });
  await expect(dashboardLink).toBeVisible();
  await expect(vendorsLink).toBeVisible();

  expect(consoleErrors).toEqual([]);
});

test("home page CTAs remain visible and tappable at the project viewport", async ({ page }) => {
  await page.goto("/");

  for (const name of ["Organization dashboard", "Vendor portal"]) {
    const link = page.getByRole("link", { name });
    await expect(link).toBeVisible();
    const box = await link.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.width).toBeGreaterThan(0);
    expect(box!.height).toBeGreaterThan(0);
  }
});

test("dashboard gates unauthenticated visitors behind wallet connection", async ({ page }) => {
  await page.goto("/dashboard");

  await expect(page.getByRole("heading", { name: "Connect your wallet" })).toBeVisible({
    timeout: 20_000,
  });
  await expect(page.getByRole("heading", { name: /Org dashboard|Welcome to Q-Trust/ })).toHaveCount(0);
});
