// Prometheus metrics endpoint (QA plan: Core.Metrics).
//
// metrics_address creates an Envoy-fronted listener (fixed host port 9902
// here). Two paths, two backends, two DIFFERENT protection surfaces:
//   /metrics        Pomerium's aggregated handler (pomerium_* + a scrape of
//                   Envoy's stats, merged) - the only path metrics_basic_auth
//                   covers.
//   /metrics/envoy  Envoy itself, prefix-rewritten to admin /stats/prometheus
//                   - NEVER behind basic auth (asserted below, so the gap is
//                   at least documented behavior).
//
// This branch also rejects malformed metrics_basic_auth at config load
// (config/options.go) instead of silently disabling authentication (the old
// ENG-4311 behavior) - TC-MET-05 is the regression guard for that fix.

import { expect, test } from "@playwright/test";
import {
  basicAuth64,
  expectMetricsPortClosed,
  metricNames,
  metricValue,
  scrapeMetrics,
} from "../helpers/metrics.js";
import { hitMarkers } from "../helpers/traffic.js";
import { startPomeriumExpectExit, withPomerium } from "../setup/containers.js";
import { generateConfig } from "../setup/pomerium-config.js";

const SCRAPER = { user: "scraper", pass: "s3cret" };

const metricsEnabledConfig = () =>
  generateConfig({ name: "met-enabled", metricsAddress: ":9902", publicAccess: true });

/** Envoy's per-request counters, summed (exact family names vary by version). */
function envoyRequestCount(body: string): number {
  return (
    metricValue(body, "envoy_cluster_upstream_rq_total") +
    metricValue(body, "envoy_http_downstream_rq_total")
  );
}

test.describe("Metrics endpoint", () => {
  test("TC-MET-01: without metrics_address the listener does not exist", async () => {
    const configFile = generateConfig({ name: "met-disabled", publicAccess: true });
    await withPomerium({ configFile }, async () => {
      await expectMetricsPortClosed();
    });
  });

  // TC-MET-02 and TC-MET-03 assert on the two paths of one identical config, so
  // they share a container rather than paying two boots for the same setup.
  test("TC-MET-02/03: /metrics aggregates Pomerium and Envoy; /metrics/envoy is raw", async () => {
    await withPomerium({ configFile: metricsEnabledConfig() }, async () => {
      await hitMarkers("met", 5);

      // The aggregated handler scrapes Envoy on demand, but Envoy flushes its
      // stats asynchronously - poll until the traffic shows up.
      await expect
        .poll(
          async () => {
            const res = await scrapeMetrics("/metrics");
            if (res.status !== 200) return `HTTP ${res.status}`;
            const names = metricNames(res.body);
            if (!names.has("pomerium_build_info")) return "no pomerium_build_info";
            if (![...names].some((n) => n.startsWith("envoy_"))) return "no envoy_* families";
            if (envoyRequestCount(res.body) === 0) return "envoy request counters still zero";
            return "ok";
          },
          {
            timeout: 30_000,
            intervals: [1_000],
            message: "/metrics never served the aggregated Pomerium + Envoy metrics",
          },
        )
        .toBe("ok");

      // The Envoy path is served by Envoy itself and rewritten to its
      // /stats/prometheus, so it carries only envoy_* families.
      const raw = await scrapeMetrics("/metrics/envoy");
      expect(raw.status).toBe(200);
      const rawNames = [...metricNames(raw.body)];
      expect(rawNames.length).toBeGreaterThan(0);
      expect(rawNames.every((n) => n.startsWith("envoy_"))).toBe(true);
    });
  });

  test("TC-MET-04: metrics_basic_auth protects /metrics but not /metrics/envoy", async () => {
    const configFile = generateConfig({
      name: "met-basic-auth",
      metricsAddress: ":9902",
      metricsBasicAuth: basicAuth64(SCRAPER.user, SCRAPER.pass),
      publicAccess: true,
    });
    await withPomerium({ configFile }, async () => {
      const noCreds = await scrapeMetrics("/metrics");
      expect(noCreds.status).toBe(401);
      expect(noCreds.headers.get("www-authenticate")).toBeTruthy();
      expect(noCreds.body).not.toContain("pomerium_build_info");

      const wrongCreds = await scrapeMetrics("/metrics", {
        auth: { user: SCRAPER.user, pass: "wrong" },
      });
      expect(wrongCreds.status).toBe(401);

      const goodCreds = await scrapeMetrics("/metrics", { auth: SCRAPER });
      expect(goodCreds.status).toBe(200);
      expect(metricNames(goodCreds.body).has("pomerium_build_info")).toBe(true);

      // The Envoy path is a separate Envoy route to the admin cluster with no
      // auth filter: full stats WITHOUT credentials. Documented gap - anyone
      // who can reach the port reads cluster names and request counts.
      const envoyNoCreds = await scrapeMetrics("/metrics/envoy");
      expect(envoyNoCreds.status).toBe(200);
      expect([...metricNames(envoyNoCreds.body)].some((n) => n.startsWith("envoy_"))).toBe(true);
    });
  });

  test("TC-MET-05: malformed metrics_basic_auth is rejected at config load", async () => {
    // Regression guard for the ENG-4311 fix: both malformed forms used to
    // silently DISABLE authentication; they must fail startup instead.
    // startPomeriumExpectExit asserts both that the error is logged and that
    // Pomerium never starts serving, so these calls ARE the assertions.
    await startPomeriumExpectExit(
      {
        configFile: generateConfig({
          name: "met-bad-auth-b64",
          metricsAddress: ":9902",
          metricsBasicAuth: "%%%not-base64%%%",
          publicAccess: true,
        }),
      },
      /metrics_basic_auth must be a base64 encoded string/,
    );

    await startPomeriumExpectExit(
      {
        configFile: generateConfig({
          name: "met-bad-auth-colon",
          metricsAddress: ":9902",
          // valid base64, but decodes to a string with no user:pass colon
          metricsBasicAuth: Buffer.from("nocolonhere").toString("base64"),
          publicAccess: true,
        }),
      },
      /user name and password separated by a colon/,
    );
  });
});
