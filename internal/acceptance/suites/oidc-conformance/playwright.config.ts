import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for the OIDC conformance e2e suite.
 *
 * One container stack (Keycloak + Pomerium + conformance suite) is booted in
 * global setup and shared by every test. Tests run serially with one worker:
 * the stack binds fixed host ports and each plan's modules run in order.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
    // Consumed by internal/acceptance/scripts/generate-summary.mjs.
    ["json", { outputFile: "results.json" }],
  ],
  outputDir: "test-results",

  // Per-module budgets are set in the spec; codereuse-30seconds alone waits 30s.
  timeout: 240_000,
  expect: { timeout: 15_000 },

  use: {
    // Pomerium serves an mkcert leaf that the browser does not trust.
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },

  globalSetup: require.resolve("./setup/global-setup"),
  globalTeardown: require.resolve("./setup/global-teardown"),

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 720 } },
    },
  ],
});
