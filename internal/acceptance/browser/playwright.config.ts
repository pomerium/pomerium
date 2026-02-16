import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for Pomerium E2E acceptance tests.
 *
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false, // Run tests sequentially for auth state consistency
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1, // Single worker for auth flow tests
  reporter: process.env.CI
    ? [
        ["blob", { outputDir: "blob-report" }],
        ["json", { outputFile: "test-results/results.json" }],
        ["list"],
      ]
    : [["list"]],
  outputDir: "../artifacts/playwright/test-results",

  // Global test settings
  use: {
    // Base URL for Pomerium app routes
    baseURL: process.env.POMERIUM_URL || "https://app.localhost.pomerium.io:8443",

    // Ignore HTTPS errors for self-signed certificates
    ignoreHTTPSErrors: true,

    // Trace on failure for debugging
    trace: "retain-on-failure",

    // Screenshots on failure
    screenshot: "only-on-failure",

    // Video on failure
    video: "retain-on-failure",

    // Timeout for each action (click, fill, etc.)
    actionTimeout: 10000,

    // Timeout for navigation
    navigationTimeout: 30000,
  },

  // Global timeout for each test
  timeout: 60000,

  // Expect timeout
  expect: {
    timeout: 10000,
  },

  // Global setup to verify environment
  globalSetup: require.resolve("./global-setup"),

  // Configure projects
  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        // Ensure consistent viewport for screenshots
        viewport: { width: 1280, height: 720 },
      },
    },
  ],
});
