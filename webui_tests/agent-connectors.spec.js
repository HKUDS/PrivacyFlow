const {test, expect} = require("@playwright/test");

test("Agent quick connect is understandable and fits the viewport", async ({page}) => {
  await page.goto("/ui/#agent-connectors");
  await expect(page.locator("#view-agent-connectors")).toHaveClass(/is-active/);
  await expect(page.locator('[data-view="detectors"]')).toHaveCount(1);

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

test("Detector configurations load and remain usable", async ({page}) => {
  await page.goto("/ui/#detectors");
  await expect(page.locator("#view-detectors")).toHaveClass(/is-active/);
  await expect(page.locator("#configuration-select")).toBeVisible();
  await expect(page.locator("#configuration-select option")).not.toHaveCount(0);
  await expect(page.locator("#detector-modules .module-row")).not.toHaveCount(0);
  await expect(page.locator("#detection-input")).toBeVisible();
  await expect(page.locator("#run-detection")).toBeVisible();
  await page.locator("#detection-input").fill("contact alice@example.com");
  await page.locator("#run-detection").click();
  await expect(page.locator("#detection-output")).toContainText("发现 1 处敏感内容");

  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport + 1);
  expect(dimensions.body).toBeLessThanOrEqual(dimensions.viewport + 1);
});

test("English dynamic detector and protected views stay localized", async ({page}) => {
  await page.goto("/ui/#detectors");
  await page.getByRole("button", {name: "EN", exact: true}).click();
  await expect(page.locator("#view-detectors")).toHaveClass(/is-active/);
  if (await page.locator("#add-module").isDisabled()) {
    await page.locator("#duplicate-configuration").click();
    await expect(page.locator("#add-module")).toBeEnabled();
  }

  await page.locator("#add-module").click();
  await expect(page.locator("#module-modal")).toBeVisible();
  await expect(page.locator("#module-modal-title")).toHaveText("Add detector module");
  await expect(page.locator("#add-regex-rule")).toHaveAttribute("aria-label", "Add regex rule");
  await page.locator("#add-regex-rule").click();
  await expect(page.locator("#module-specific-fields")).toContainText("Rule name");
  await expect(page.locator("#module-specific-fields")).toContainText("Regular expression");
  await expect(page.locator("#module-specific-fields")).not.toContainText(/[\u3400-\u9fff]/);
  await page.locator('#module-modal [data-close-modal]').first().click();

  await page.locator('.nav-item[data-view="protected"]').click();
  await expect(page.locator("#view-protected")).toHaveClass(/is-active/);
  await page.locator("#protected-show-raw").click();
  await expect(page.locator("#confirm-title")).toHaveText("Show protected originals");
  await expect(page.locator("#confirm-message")).toContainText("active local mappings");
  await page.locator('#confirm-modal [data-close-modal]').first().click();

  const untranslated = await page.evaluate(() => {
    const chinese = /[\u3400-\u9fff]/;
    const results = [];
    const view = document.querySelector(".view.is-active");
    const walker = document.createTreeWalker(view || document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const value = (node.nodeValue || "").trim();
      if (value && chinese.test(value) && !node.parentElement?.closest('[data-locale="zh"]')) results.push(value);
    }
    for (const element of (view || document).querySelectorAll("[placeholder], [title], [aria-label]")) {
      for (const attribute of ["placeholder", "title", "aria-label"]) {
        const value = element.getAttribute(attribute) || "";
        if (chinese.test(value)) results.push(`${attribute}: ${value}`);
      }
    }
    return results;
  });
  expect(untranslated).toEqual([]);
});

test("English UI does not retain Chinese interface copy", async ({page}) => {
  await page.goto("/ui/#overview");
  await page.getByRole("button", {name: "EN", exact: true}).click();

  for (const view of ["overview", "audit", "protected", "detectors", "local-models", "agent-connectors"]) {
    await page.locator(`.nav-item[data-view="${view}"]`).click();
    await expect(page.locator(`#view-${view}`)).toHaveClass(/is-active/);
  }

  const untranslated = await page.evaluate(() => {
    const chinese = /[\u3400-\u9fff]/;
    const results = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      const value = (node.nodeValue || "").trim();
      if (!value || !chinese.test(value) || node.parentElement?.closest('[data-locale="zh"]')) continue;
      results.push({kind: "text", value});
    }
    for (const element of document.querySelectorAll("[placeholder], [title], [aria-label]")) {
      for (const attribute of ["placeholder", "title", "aria-label"]) {
        const value = element.getAttribute(attribute) || "";
        if (chinese.test(value)) results.push({kind: attribute, value});
      }
    }
    return results;
  });

  expect(untranslated).toEqual([]);
});
