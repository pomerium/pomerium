import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for the container-based observability e2e suite
 * (logging / metrics / tracing).
 *
 * The config-invariant services (Keycloak, the pomerium/verify upstream, and
 * the Jaeger collector) are booted once in global setup and torn down in
 * global teardown; Pomerium itself starts per test with that case's generated
 * configuration. Tests run serially with a single worker because the stack
 * binds fixed host ports (8443 / 8080 / 9902 / 16686) and is shared across
 * tests.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  // The suite restarts the Pomerium container per test, which churns the
  // runner's Docker network; a page.goto that races a restart aborts with
  // ERR_NETWORK_CHANGED. Retry under CI (as the other harnesses do) so a single
  // such abort self-heals; see also the launchOptions flag below. Every test
  // starts its own Pomerium in the test body, so a retry re-creates the whole
  // arrangement instead of reusing a torn-down container.
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

  // Browser sign-in, container restarts, and span-export polling need
  // generous budgets.
  timeout: 120_000,
  expect: { timeout: 15_000 },

  use: {
    // Stop Chromium aborting navigations with ERR_NETWORK_CHANGED when it
    // notices the network reconfigure (the per-test Pomerium container
    // restarts trigger this on CI runners). Unknown feature names are ignored
    // safely.
    launchOptions: { args: ["--disable-features=NetworkChangeNotifier"] },
    // Pomerium serves a leaf certificate from the local mkcert CA; the
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
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 720 } },
    },
  ],
});
