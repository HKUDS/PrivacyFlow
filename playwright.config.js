const {defineConfig, devices} = require("@playwright/test");
const {existsSync} = require("node:fs");

const python = process.env.PF_PLAYWRIGHT_PYTHON || (existsSync(".venv/bin/python") ? ".venv/bin/python" : "python");

module.exports = defineConfig({
  testDir: "./webui_tests",
  reporter: "line",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:9876",
    locale: "zh-CN",
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "desktop-chromium",
      use: {...devices["Desktop Chrome"], viewport: {width: 1440, height: 1000}},
    },
    {
      name: "mobile-chromium",
      use: {...devices["iPhone 13"], browserName: "chromium", viewport: {width: 390, height: 844}},
    },
  ],
  webServer: {
    command: `PF_HOST=127.0.0.1 PF_PORT=9876 PF_DATABASE_PATH=/tmp/privacyflow-playwright/state.sqlite3 PF_AUDIT_LOG_PATH=/tmp/privacyflow-playwright/audit.jsonl PF_STRICT=false ${python} -m gateway.cli --launcher-config /tmp/privacyflow-playwright/launcher.json`,
    url: "http://127.0.0.1:9876/ui/",
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
