// Marker paths, the Keycloak sign-in round trip, and requests against the route.
//
// Specs needing no identity use a PUBLIC route (zero sign-in noise in logs and
// spans); specs asserting identity fields sign in through the real Keycloak form.

import { expect, request, type APIResponse, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { submitLoginForm, waitForKeycloakLoginPage } from "../../shared/keycloak-login.js";
import { KEYCLOAK_HOSTNAME, TEST_USER, VERIFY_URL } from "../setup/constants.js";
import { gotoStable } from "./nav.js";

/**
 * A unique path per test, e.g. /e2e/trc-01-4f9a02c1. The upstream 404s it, which
 * is fine: logs and spans record path and status either way, and the uniqueness
 * is what scopes assertions to this test's own traffic.
 */
export function markerPath(prefix: string): string {
  return `/e2e/${prefix}-${randomUUID().slice(0, 8)}`;
}

/** Chromium parks here when a navigation is aborted at the network level. */
function parkedOnErrorPage(page: Page): boolean {
  return page.url().startsWith("chrome-error://");
}

/**
 * Drive the full OIDC round trip and return once the browser is back on the
 * route host. Retried as a unit: the chain (route -> authenticate -> Keycloak ->
 * back) has hops the test does not drive, and on CI one can be aborted by the
 * Docker network reconfiguring after a container start. gotoStable protects only
 * the first navigation.
 */
export async function signIn(page: Page, fromUrl: string, attempts = 3): Promise<void> {
  const routeHostname = new URL(fromUrl).hostname;
  for (let attempt = 1; ; attempt++) {
    try {
      await gotoStable(page, fromUrl, { waitUntil: "domcontentloaded" });
      // A retry can land already signed in, with no form to fill.
      if (!parkedOnErrorPage(page) && new URL(page.url()).hostname === routeHostname) return;
      await waitForKeycloakLoginPage(page, KEYCLOAK_HOSTNAME);
      await submitLoginForm(page, TEST_USER.email, TEST_USER.password);
      await page.waitForURL((url) => url.hostname === routeHostname);
      return;
    } catch (err) {
      const transient = parkedOnErrorPage(page) || /ERR_NETWORK_CHANGED|ERR_CONNECTION/.test(String(err));
      if (attempt >= attempts || !transient) throw err;
      await page.waitForTimeout(1_000);
    }
  }
}

/**
 * Open a unique marker path IN THE BROWSER. `headers` goes on the page, not the
 * request - a navigation cannot carry per-request headers.
 */
export async function openMarker(
  page: Page,
  prefix: string,
  opts: { headers?: Record<string, string> } = {},
): Promise<string> {
  const marker = markerPath(prefix);
  if (opts.headers) await page.setExtraHTTPHeaders(opts.headers);
  await gotoStable(page, `${VERIFY_URL}${marker}`, { waitUntil: "domcontentloaded" });
  return marker;
}

/** GET paths concurrently through one throwaway request context. */
export async function getPaths(
  paths: string[],
  opts: { headers?: Record<string, string> } = {},
): Promise<APIResponse[]> {
  const ctx = await request.newContext({ ignoreHTTPSErrors: true });
  try {
    return await Promise.all(
      paths.map((p) => ctx.get(`${VERIFY_URL}${p}`, { headers: opts.headers })),
    );
  } finally {
    await ctx.dispose();
  }
}

/**
 * GET `count` unique marker paths. Asserts each reached the upstream: a 5xx would
 * make any later "no spans" / "no log entry" assertion vacuous.
 */
export async function hitMarkers(prefix: string, count = 1): Promise<string[]> {
  const markers = Array.from({ length: count }, () => markerPath(prefix));
  const responses = await getPaths(markers);
  for (const res of responses) {
    expect(res.status(), `request to the protected route failed`).toBeLessThan(500);
  }
  return markers;
}

/** hitMarkers for the single-request case. */
export async function hitMarker(prefix: string): Promise<string> {
  const [marker] = await hitMarkers(prefix, 1);
  return marker;
}
