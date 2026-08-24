import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const TAGS = ["wcag2a", "wcag2aa", "best-practice"];

function seriousViolations(violations: Awaited<ReturnType<typeof analyze>>) {
  return violations.filter((v) => v.impact === "critical" || v.impact === "serious");
}

async function analyze(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  for (const violation of results.violations) {
    if (violation.impact === "critical" || violation.impact === "serious") {
      continue;
    }
    console.warn(
      `[a11y] ${violation.id} (${violation.impact ?? "unknown"}): ${violation.nodes.length} node(s), tags: ${violation.tags.join(", ")}`,
    );
  }
  return results.violations;
}

test.describe("home page a11y", () => {
  test("/ has no critical or serious wcag2a/wcag2aa/best-practice violations", async ({ page }) => {
    await page.goto("/");
    const violations = await analyze(page);
    expect(seriousViolations(violations)).toEqual([]);
  });
});

test.describe("verification page a11y", () => {
  test.skip(
    process.env.QTRUST_E2E_PUBLIC_PAGE !== "1",
    "/v/[id] requires live backend asset data; set QTRUST_E2E_PUBLIC_PAGE=1 (and optionally QTRUST_E2E_ASSET_ID) to scan it",
  );

  test("/v/[id] has no critical or serious wcag2a/wcag2aa/best-practice violations", async ({ page }) => {
    const assetId = process.env.QTRUST_E2E_ASSET_ID ?? `0x${"0".repeat(64)}`;
    const response = await page.goto(`/v/${assetId}`);
    if (!response || response.status() !== 200) {
      test.skip(true, `/v/[id] not renderable without backend data (status ${response?.status() ?? "network-error"})`);
      return;
    }
    const violations = await analyze(page);
    expect(seriousViolations(violations)).toEqual([]);
  });
});
