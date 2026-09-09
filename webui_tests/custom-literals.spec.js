const {test, expect} = require("@playwright/test");

test("Watchlist section is visible and fits the viewport", async ({page}) => {
  await page.goto("/ui/#detectors");
  await expect(page.locator("#view-detectors")).toHaveClass(/is-active/);
  await expect(page.locator("#custom-literals-section")).toBeVisible();
  await expect(page.locator("#custom-literal-input")).toBeVisible();
  await expect(page.locator("#custom-literals-form button[type=submit]")).toBeVisible();

  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.viewport + 1);
});

test("Workspace watchlist adds, detects duplicates, and removes a custom value", async ({page}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-chromium", "Watchlist writes cannot run in parallel against one server");

  await page.goto("/ui/#detectors");
  await expect(page.locator("#custom-literal-input")).toBeVisible();

  const value = `watchlist-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  await page.locator("#custom-literal-input").fill(value);
  await page.locator("#custom-literals-form button[type=submit]").click();

  const chip = page.locator("#custom-literals-list .custom-literal-chip").filter({hasText: value});
  await expect(chip).toHaveCount(1);
  await expect(page.locator("#toast")).toContainText("观察名单已更新");

  await page.locator("#custom-literal-input").fill(`${value.slice(0, 9)}\u200b${value.slice(9)}`);
  await page.locator("#custom-literals-form button[type=submit]").click();
  await expect(page.locator("#toast")).toContainText("该值已在观察名单中");
  await expect(chip).toHaveCount(1);

  await page.locator("#detection-input").fill(`prefix ${value} suffix`);
  await page.locator("#run-detection").click();
  await expect(page.locator("#detection-output")).toContainText("自定义保护值");

  await chip.getByRole("button").click();
  await expect(page.locator("#custom-literals-list")).not.toContainText(value);
});
