import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for the downstream mTLS e2e suite.
 *
 * This project runs inside the mcr.microsoft.com/playwright container; the Go
 * harness provides target URLs and credentials via environment variables and
 * bind-mounts ARTIFACTS_DIR so reports/traces survive the container.
 */
const artifactsDir = process.env.ARTIFACTS_DIR ?? "./artifacts";

export default defineConfig({
  testDir: "./tests",
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: `${artifactsDir}/report`, open: "never" }],
    ["json", { outputFile: `${artifactsDir}/results.json` }],
  ],
  outputDir: `${artifactsDir}/test-results`,

  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },

  use: {
    // Pomerium serves a self-signed certificate generated per run.
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
  },

  projects: [
    {
      name: "chromium",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 720 },
      },
    },
  ],
});
