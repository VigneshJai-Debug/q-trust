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

  expect(consoleErrors).toEqual([]);
});
