// Traffic generation: marker paths, the Keycloak sign-in round trip, and
// requests against the protected route.
//
// Convention: specs that do not need an identity use a PUBLIC route and drive
// it with these helpers (zero sign-in noise in logs/spans); specs that assert
// identity fields sign in through the real Keycloak form once and then reuse
// the page's cookie-sharing request context.

import { expect, request, type APIResponse, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { submitLoginForm, waitForKeycloakLoginPage } from "../../shared/keycloak-login.js";
import { KEYCLOAK_HOSTNAME, TEST_USER, VERIFY_URL } from "../setup/constants.js";
import { gotoStable } from "./nav.js";

/**
 * A unique request path for one test, e.g. /e2e/trc-01-4f9a02c1. The upstream
 * 404s unknown paths, which is fine - access logs and spans record the path
 * and status either way, and the uniqueness is what scopes every assertion to
 * this test's own traffic.
 */
export function markerPath(prefix: string): string {
  return `/e2e/${prefix}-${randomUUID().slice(0, 8)}`;
}

/** Chromium parks here when a navigation is aborted at the network level. */
function parkedOnErrorPage(page: Page): boolean {
  return page.url().startsWith("chrome-error://");
}

/**
 * Drive the full OIDC round trip on a protected route: navigate, sign in as
 * the shared test user on the Keycloak form, and wait for the redirect back.
 *
 * Retried as a unit. The sign-in walks a redirect chain the test does not
 * drive (route -> authenticate -> Keycloak -> back), and on CI a hop can be
 * aborted when the Docker network reconfigures just after the per-test
 * container start - Chromium then parks on an error page and the wait for the
 * final URL times out. gotoStable protects the first navigation only, so the
 * chain needs its own retry.
 */
export async function signIn(page: Page, fromUrl: string, attempts = 3): Promise<void> {
  const routeHostname = new URL(fromUrl).hostname;
  for (let attempt = 1; ; attempt++) {
    try {
      await gotoStable(page, fromUrl, { waitUntil: "domcontentloaded" });
      // A retry after a partially completed flow can land already signed in,
      // in which case there is no login form to fill.
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
 * Open a unique marker path on the protected route IN THE BROWSER and return
 * the marker. `headers` is applied to the page rather than the request, since a
 * navigation cannot carry per-request headers.
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

/**
 * GET one or more paths on the protected route concurrently, through a single
 * throwaway request context.
 */
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
 * GET `count` unique marker paths and return the markers. Asserts each request
 * reached the upstream (a 5xx would mean the traffic never got there, making
 * any later "no spans"/"no log entry" assertion vacuous).
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
