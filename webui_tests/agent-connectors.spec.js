const {test, expect} = require("@playwright/test");

test("Agent quick connect is understandable and fits the viewport", async ({page}) => {
  await page.goto("/ui/#agent-connectors");
  await expect(page.locator("#view-agent-connectors")).toHaveClass(/is-active/);
  await expect(page.locator('[data-view="detectors"]')).toHaveCount(0);

  const rows = page.locator("#connector-list .connector-row");
  await expect(rows).toHaveCount(4);
  for (const icon of [
    "agent-codex.svg",
    "agent-claude-code.svg",
    "agent-deepseek-harness.svg",
    "agent-nanobot.svg",
  ]) {
    await expect(page.locator(`#connector-list img[src$="${icon}"]`)).toHaveCount(1);
  }

  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.viewport + 1);
});
