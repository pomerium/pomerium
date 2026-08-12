import * as path from "node:path";
import { defineConfig, devices } from "@playwright/test";

// Saved browser session produced by the setup project (tests/auth.setup.ts) and
// reused by the test project. Mirrors STORAGE_STATE in setup/constants.ts.
const STORAGE_STATE = path.join(__dirname, ".auth", "user.json");

/**
 * Playwright configuration for the container-based upstream TLS/mTLS e2e suite.
 *
 * The whole stack - Keycloak, the pomerium/verify control upstream, the
 * first-party Node TLS/mTLS echo upstreams, and a single shared Pomerium
 * serving every behavior route from one generated config - is booted once in
 * global setup and torn down in global teardown. Specs never restart Pomerium;
 * only config-validation.spec.ts boots extra throwaway (port-less) containers.
 * Tests run serially with a single worker because the stack binds fixed host
 * ports (8443 / 8080) and is shared.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  // Container churn on the shared Docker network (the config-validation spec
  // boots throwaway Pomerium containers mid-run; testcontainers starts and
  // stops the rest around the run) can make Chromium on CI runners abort an
  // in-flight navigation with ERR_NETWORK_CHANGED. Retry under CI (as the
  // browser suite does) so a single such abort self-heals; see also the
  // launchOptions flag below.
  retries: process.env.CI ? 2 : 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
    // Machine-readable results consumed by the shared acceptance summary
    // aggregator (internal/acceptance/scripts/generate-summary.mjs), which
    // merges every harness's results.json into one Feature Coverage table.
    ["json", { outputFile: "results.json" }],
  ],
  outputDir: "test-results",

  // Browser sign-in plus container round-trips need generous budgets.
  timeout: 120_000,
  expect: { timeout: 15_000 },

  use: {
    // Stop Chromium aborting navigations with ERR_NETWORK_CHANGED when it
    // notices the network reconfigure (Docker network churn from container
    // starts/stops - e.g. the config-validation throwaway containers - can
    // trigger this on CI runners). Unknown feature names are ignored safely.
    launchOptions: { args: ["--disable-features=NetworkChangeNotifier"] },
    // Pomerium serves a leaf certificate from the per-run OpenSSL CA; the
    // browser simply ignores certificate errors.
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
    // Logs in once through the IdP (real browser) and saves the session.
    {
      name: "setup",
      testMatch: /.*\.setup\.ts/,
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 720 } },
    },
    // Config-load validation: boots throwaway config-error containers and reads
    // their logs — no browser and no login. Its own project (no storageState,
    // no setup dependency) so an IdP flake can't red-wall these cases.
    {
      name: "config",
      testMatch: /config-validation\.spec\.ts/,
    },
    // Every behavior spec runs as the already-authenticated user.
    {
      name: "chromium",
      dependencies: ["setup"],
      testIgnore: /config-validation\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1280, height: 720 },
        storageState: STORAGE_STATE,
      },
    },
  ],
});
