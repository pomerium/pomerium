import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for the container-based Pomerium MCP e2e suite.
 *
 * A single shared container stack (Keycloak + upstream MCP server + Pomerium)
 * is booted once in global setup and torn down in global teardown. Tests run
 * serially with a single worker because the stack binds fixed host ports
 * (8443 / 8080) and is shared across tests.
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
  ],
  outputDir: "test-results",

  // OAuth browser sign-in plus container round-trips need generous budgets.
  timeout: 120_000,
  expect: { timeout: 15_000 },

  use: {
    // Pomerium serves an mkcert leaf; trust is handled out of band (browser
    // ignores cert errors here; the MCP client trusts the CA via
    // NODE_EXTRA_CA_CERTS).
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
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
