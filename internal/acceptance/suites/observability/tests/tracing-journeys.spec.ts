// Real user journeys, verified through the Jaeger UI (QA plan: Core.OTEL Tracing).
//
// The other tracing specs read spans back with `fetch`. These four sign in with a
// real browser, then open the Jaeger UI IN THE SAME BROWSER, with the Jaeger
// interaction written out in the test body rather than behind a helper.
//
// Non-obvious facts these tests rely on, measured against the pinned Jaeger:
//   - Signing in ON a path yields TWO traces for it: the refused request (302),
//     with the sign-in chain stitched in by trace-id propagation
//     (authorize/check_response.go), and the retry (200) as its own trace.
//   - A plain proxied request's trace holds only Envoy + Control Plane (the
//     ext_authz server) + Authorize. Proxy / Authenticate / Data Broker appear
//     in the sign-in trace instead.
//   - Pomerium's own endpoints get Envoy's `internal:` decorator; only policy
//     routes get `ingress:` (config/envoyconfig/routes.go).
//   - Keycloak is not behind Envoy, so it contributes no span.
//   - Envoy does not error-flag 4xx: a 403 shows only as http.status_code.
//
// Topology exactness and sampler behaviour live in
// internal/testenv/selftests/tracing_test.go. Bumping JAEGER_IMAGE means
// re-capturing the UI locators below.

import { expect, test } from "@playwright/test";
import { gotoStable } from "../helpers/nav.js";
import { markerPath, signIn } from "../helpers/traffic.js";
import { withPomerium } from "../setup/containers.js";
import {
  AUTHENTICATE_HOSTNAME,
  JAEGER_QUERY_URL,
  TEST_USER,
  UPSTREAM_URL,
  VERIFY_HOSTNAME,
  VERIFY_URL,
} from "../setup/constants.js";
import { TRACING_TO_JAEGER, generateConfig } from "../setup/pomerium-config.js";

// A sign-in plus a second web UI does not fit the suite's 120s default when a
// Pomerium start runs long (the start alone is allowed 75s).
test.describe.configure({ timeout: 240_000, retries: 1 });

/** The URL Jaeger's own search form produces; it runs the search on load. */
const JAEGER_SEARCH_ENVOY = `${JAEGER_QUERY_URL}/search?service=Envoy&lookback=1h&limit=200`;

/**
 * Jaeger fetches on page load, so a stale DOM never changes: assertions inside a
 * reload loop must fail fast instead of spending the 15s default on old HTML.
 */
const FAIL_FAST = { timeout: 1_000 };

/** The find box counts matches across the WHOLE trace, unlike the virtualized timeline. */
const AT_LEAST_ONE_MATCH = /^[1-9]\d*$/;

test.describe("Tracing journeys through the Jaeger UI", () => {
  test("TC-TRC-20: a signed-in user finds and reads their request's trace", async ({ page }) => {
    // Route:  https://verify.localhost.pomerium.io:8443 -> http://upstream:8000
    //         allow_any_authenticated_user: true
    // Config: otel_traces_exporter: otlp
    //         otel_exporter_otlp_endpoint: http://jaeger:4318
    //         otel_bsp_schedule_delay: 1000
    const configFile = generateConfig({
      name: "trc-journey-signin",
      settings: {
        ...TRACING_TO_JAEGER,
      },
    });

    await withPomerium({ configFile }, async () => {
      const marker = markerPath("trc20");

      await test.step(`${TEST_USER.email} opens the protected route and signs in`, async () => {
        await signIn(page, VERIFY_URL);
      });

      await test.step(`they browse to ${marker}`, async () => {
        const response = await gotoStable(page, `${VERIFY_URL}${marker}`, {
          waitUntil: "domcontentloaded",
        });
        // The upstream 404s unknown paths; only a 5xx would mean no ingress span exists.
        expect(response?.status(), "the request reached the upstream").toBeLessThan(500);
      });

      await test.step("they open the Jaeger UI and search Envoy's traces", async () => {
        await gotoStable(page, `${JAEGER_QUERY_URL}/search`, { waitUntil: "domcontentloaded" });

        // The Service list is fetched on page load, so reload until Envoy appears.
        const envoyOption = page.locator(".ant-select-item-option").filter({ hasText: "Envoy" });
        await expect(async () => {
          await page.reload();
          await page.getByTestId("service").click();
          // Typing filters the list, which also guarantees the option renders.
          // Matched by class, not role: rc-select tags only a few with role="option".
          await page.keyboard.type("Envoy");
          await expect(envoyOption).toBeVisible({ timeout: 2_000 });
        }).toPass({ timeout: 30_000 });

        await envoyOption.click();
        await page.getByRole("button", { name: /find traces/i }).click();
      });

      // One row per trace, titled with its root span - here Envoy's ingress span.
      const traceRow = page.getByRole("row").filter({ hasText: marker });

      await test.step("they refresh until the trace shows Pomerium's own services", async () => {
        // Envoy exports on the 1s delay above, Pomerium's SDK on ~5s. Waiting for
        // Control Plane in the row means the trace is complete before it is
        // opened - the UI caches a fetched trace, so opening early pins a partial one.
        await expect(async () => {
          await page.reload();
          await expect(traceRow).toHaveCount(1, FAIL_FAST);
          await expect(traceRow).toContainText("Envoy", FAIL_FAST);
          await expect(traceRow, "the ext_authz check").toContainText("Control Plane", FAIL_FAST);
          await expect(traceRow, "the authorize decision").toContainText("Authorize", FAIL_FAST);
        }).toPass({ timeout: 30_000 });
      });

      await test.step("they click into the trace", async () => {
        await page.getByRole("link").filter({ hasText: marker }).first().click();
        await page.waitForURL(/\/trace\/[0-9a-f]{32}/);
      });

      await test.step("the trace shows Envoy's ingress span for exactly their request", async () => {
        // Timeline rows read "<service> <span name> <status>".
        const ingressSpan = page.locator("a.span-name").filter({ hasText: marker }).first();
        await expect(ingressSpan).toBeVisible();
        await expect(ingressSpan).toContainText("Envoy");
        await expect(ingressSpan).toContainText("ingress:");
        await expect(ingressSpan).toContainText(`${VERIFY_HOSTNAME}:8443${marker}`);
      });

      await test.step("...and that Pomerium's own spans share that trace", async () => {
        await page.getByPlaceholder("Find...").fill("Control Plane");
        await expect(page.locator(".TracePageSearchBar")).toHaveText(AT_LEAST_ONE_MATCH);
      });
    });
  });

  test("TC-TRC-21: the sign-in itself is traced, and the retry is its own trace", async ({
    page,
  }) => {
    // Route:  https://verify.localhost.pomerium.io:8443 -> http://upstream:8000
    //         allow_any_authenticated_user: true
    // Config: otel_traces_exporter: otlp
    //         otel_exporter_otlp_endpoint: http://jaeger:4318
    //         otel_bsp_schedule_delay: 1000
    const configFile = generateConfig({
      name: "trc-journey-signin-flow",
      settings: {
        ...TRACING_TO_JAEGER,
      },
    });

    await withPomerium({ configFile }, async () => {
      const marker = markerPath("trc21");

      await test.step(`a signed-out user opens ${marker} and signs in there`, async () => {
        // This requests the marker path twice: once with no session, once after.
        await signIn(page, `${VERIFY_URL}${marker}`);
      });

      await test.step("they open the Jaeger UI at Envoy's traces", async () => {
        await gotoStable(page, JAEGER_SEARCH_ENVOY, { waitUntil: "domcontentloaded" });
      });

      const markerRows = page.getByRole("row").filter({ hasText: marker });

      await test.step("that one path produced TWO traces", async () => {
        await expect(async () => {
          await page.reload();
          await expect(markerRows).toHaveCount(2, FAIL_FAST);
          // Only the sign-in trace has Authenticate, and it arrives last.
          await expect(markerRows.filter({ hasText: "Authenticate" })).toHaveCount(1, FAIL_FAST);
        }).toPass({ timeout: 30_000 });
      });

      await test.step("they open the one that carries the sign-in", async () => {
        await markerRows.filter({ hasText: "Authenticate" }).getByRole("link").first().click();
        await page.waitForURL(/\/trace\/[0-9a-f]{32}/);
      });

      await test.step("it begins with the refused request that started the sign-in", async () => {
        const refused = page.locator("a.span-name").filter({ hasText: marker }).first();
        await expect(refused).toContainText("ingress:");
        // The 302 to the authenticate service is what tells this trace from its twin.
        await expect(refused).toContainText("302");
      });

      const signInHops = [
        `${AUTHENTICATE_HOSTNAME}:8443/.pomerium/sign_in`,
        `${AUTHENTICATE_HOSTNAME}:8443/oauth2/callback`,
        `${VERIFY_HOSTNAME}:8443/.pomerium/callback/`,
      ];

      for (const hop of signInHops) {
        await test.step(`the same trace contains the ${hop} hop`, async () => {
          await page.getByPlaceholder("Find...").fill(hop);
          await expect(page.locator(".TracePageSearchBar")).toHaveText(AT_LEAST_ONE_MATCH);
        });
      }

      await test.step("and the authenticate service contributed its own spans", async () => {
        await page.getByPlaceholder("Find...").fill("Authenticate");
        await expect(page.locator(".TracePageSearchBar")).toHaveText(AT_LEAST_ONE_MATCH);
      });
    });
  });

  test("TC-TRC-22: the trace id the upstream received opens that trace in Jaeger", async ({
    page,
  }) => {
    // Route:  https://verify.localhost.pomerium.io:8443 -> http://upstream:8000
    //         allow_any_authenticated_user: true
    // Config: otel_traces_exporter: otlp
    //         otel_exporter_otlp_endpoint: http://jaeger:4318
    //         otel_bsp_schedule_delay: 1000
    const configFile = generateConfig({
      name: "trc-journey-traceparent",
      settings: {
        ...TRACING_TO_JAEGER,
      },
    });

    await withPomerium({ configFile }, async () => {
      let traceId = "";

      await test.step("they sign in and open the page that echoes their request headers", async () => {
        await signIn(page, VERIFY_URL);
        // /headers echoes every header received; /json returns only the claims.
        const response = await gotoStable(page, `${VERIFY_URL}/headers`, {
          waitUntil: "domcontentloaded",
        });
        expect(response?.status(), "the upstream served /headers").toBe(200);
      });

      await test.step("they read the traceparent off the page", async () => {
        // Go's http.Header serializes as {"Traceparent": ["..."]}.
        const headers = JSON.parse(await page.locator("body").innerText()) as Record<
          string,
          string[]
        >;
        const name = Object.keys(headers).find((k) => k.toLowerCase() === "traceparent");
        expect(name, `no traceparent among: ${Object.keys(headers).join(", ")}`).toBeDefined();

        const traceparent = String(headers[name!]);
        // version-traceid-spanid-flags; the trailing 01 means sampled.
        expect(traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
        traceId = traceparent.split("-")[1];
      });

      await test.step("they open that exact trace id in the Jaeger UI", async () => {
        // Pomerium spawns a fresh upstream span, so only the TRACE id matches.
        await gotoStable(page, `${JAEGER_QUERY_URL}/trace/${traceId}`, {
          waitUntil: "domcontentloaded",
        });

        await expect(async () => {
          await page.reload();
          const ingressSpan = page
            .locator("a.span-name")
            .filter({ hasText: `${VERIFY_HOSTNAME}:8443/headers` })
            .first();
          await expect(
            ingressSpan,
            "the trace named by the page's own header is the trace of its own request",
          ).toBeVisible(FAIL_FAST);
          await expect(ingressSpan).toContainText("Envoy", FAIL_FAST);
          await expect(ingressSpan).toContainText("ingress:", FAIL_FAST);
        }).toPass({ timeout: 30_000 });
      });
    });
  });

  test("TC-TRC-23: a request refused by policy is still traced, with its 403", async ({ page }) => {
    // Route:  https://verify.localhost.pomerium.io:8443 -> http://upstream:8000
    //         policy: authenticated_user AND email is bob@example.com
    //         so alice clears the sign-in gate, then fails the email rule: 403,
    //         not another sign-in redirect.
    // Config: otel_traces_exporter: otlp
    //         otel_exporter_otlp_endpoint: http://jaeger:4318
    //         otel_bsp_schedule_delay: 1000
    const configFile = generateConfig({
      name: "trc-journey-denied",
      settings: {
        ...TRACING_TO_JAEGER,
        routes: [
          {
            from: VERIFY_URL,
            to: UPSTREAM_URL,
            pass_identity_headers: true,
            policy: [
              {
                allow: {
                  and: [{ authenticated_user: true }, { email: { is: "bob@example.com" } }],
                },
              },
            ],
          },
        ],
      },
    });

    await withPomerium({ configFile }, async () => {
      const marker = markerPath("trc23");

      await test.step(`${TEST_USER.email} signs in, and the route refuses them`, async () => {
        // signIn returns once back on the route host - here, the 403 page.
        await signIn(page, VERIFY_URL);
      });

      await test.step(`they try ${marker} anyway and are refused again`, async () => {
        const response = await gotoStable(page, `${VERIFY_URL}${marker}`, {
          waitUntil: "domcontentloaded",
        });
        expect(response?.status(), "a signed-in user their policy excludes gets 403").toBe(403);
      });

      await test.step("they open the Jaeger UI at Envoy's traces", async () => {
        await gotoStable(page, JAEGER_SEARCH_ENVOY, { waitUntil: "domcontentloaded" });
      });

      const traceRow = page.getByRole("row").filter({ hasText: marker });

      await test.step("the refused request has a trace, with Pomerium's spans in it", async () => {
        await expect(async () => {
          await page.reload();
          await expect(traceRow).toHaveCount(1, FAIL_FAST);
          // The denial IS an authorize decision, so authorize must be in the trace.
          await expect(traceRow).toContainText("Authorize", FAIL_FAST);
        }).toPass({ timeout: 30_000 });
      });

      await test.step("they open it and read the refusal off the trace", async () => {
        await page.getByRole("link").filter({ hasText: marker }).first().click();
        await page.waitForURL(/\/trace\/[0-9a-f]{32}/);

        const ingressSpan = page.locator("a.span-name").filter({ hasText: marker }).first();
        await expect(ingressSpan).toContainText("Envoy");
        await expect(ingressSpan).toContainText("ingress:");
        await expect(ingressSpan, "the span row carries the status they saw").toContainText("403");
      });

      await test.step("...and the status is on the span itself, not just the row", async () => {
        await page.getByPlaceholder("Find...").fill("http.status_code=403");
        await expect(page.locator(".TracePageSearchBar")).toHaveText(AT_LEAST_ONE_MATCH);
      });
    });
  });
});
