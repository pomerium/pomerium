/**
 * Hosted-authenticate (https://authenticate.pomerium.app) helpers for the
 * `tests/hosted/` suite.
 *
 * Every selector and copy string for the REAL cloud sign-in / sign-out UI
 * lives ONLY in this module, so a hosted UI redesign is a one-file fix (see
 * the "Hosted authenticate suite" section of internal/acceptance/README.md
 * for the re-capture procedure).
 *
 * Live-UI facts (captured 2026-08-21): the sign-in page is a JS-rendered app
 * whose inputs carry no labels, names, or placeholders - only type attributes;
 * the submit button is "Login" and stays DISABLED while either field is empty
 * (so empty submissions are impossible and no native validation message ever
 * appears); rejected credentials render a role="alert" MUI element reading
 * "The supplied auth credential is malformed or has expired."
 *
 * Env contract:
 *   HOSTED_E2E=1            - enables the suite (services: `make up-hosted`)
 *   HOSTED_TEST_EMAIL       - real hosted-IdP account (positive-path tests)
 *   HOSTED_TEST_PASSWORD    - its password
 */

import { APIResponse, Page, Locator, test, expect } from "@playwright/test";
import { urls, paths, timeouts, headerNames, cookieNames } from "../fixtures/test-data.js";

export interface HostedUser {
  email: string;
  password: string;
}

/** Hostname of the hosted authenticate service (env-overridable via urls). */
export const HOSTED_HOSTNAME = new URL(urls.hostedAuthenticate).hostname;

// ---------------------------------------------------------------------------
// Env gating
// ---------------------------------------------------------------------------

/**
 * Skip the enclosing scope unless the hosted e2e suite is enabled
 * (`make test-suite-hosted` sets HOSTED_E2E=1). Call once per describe.
 */
export function skipUnlessHostedE2E(): void {
  test.skip(
    !process.env.HOSTED_E2E,
    "hosted e2e disabled - run via `make test-suite-hosted` (HOSTED_E2E=1)"
  );
}

/**
 * Hosted-IdP account for positive-path tests: skips the test when the
 * credentials env vars are unset, and returns a non-null user otherwise.
 * Never hardcode credentials.
 */
export function requireHostedUser(): HostedUser {
  const email = process.env.HOSTED_TEST_EMAIL;
  const password = process.env.HOSTED_TEST_PASSWORD;
  test.skip(!email || !password, "HOSTED_TEST_EMAIL / HOSTED_TEST_PASSWORD not set");
  return { email: email!, password: password! };
}

/**
 * A clearly-fake unique address for invalid-credential tests. Never uses the
 * real account, so repeated failures cannot lock it out.
 */
export function randomInvalidEmail(): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return `e2e-invalid-${Date.now()}-${rand}@invalid.pomerium.test`;
}

// ---------------------------------------------------------------------------
// Sign-in form (JS-rendered app - always wait for the rendered inputs, never
// for page text; the inputs are only reachable by their type attributes).
// ---------------------------------------------------------------------------

function emailInput(page: Page): Locator {
  return page.locator('input[type="email"]').first();
}

function passwordInput(page: Page): Locator {
  return page.locator('input[type="password"]').first();
}

function signInButton(page: Page): Locator {
  return page.getByRole("button", { name: /log ?in/i }).first();
}

/** Wait until the redirect chain lands on the hosted sign-in form. */
export async function waitForHostedSignInPage(page: Page): Promise<void> {
  await page.waitForURL((url) => url.hostname === HOSTED_HOSTNAME, {
    timeout: timeouts.long,
  });
  await expect(
    passwordInput(page),
    "hosted sign-in form should render (JS app)"
  ).toBeVisible({ timeout: timeouts.long });
}

/** Fill and submit the hosted email/password form. */
export async function submitHostedLoginForm(page: Page, user: HostedUser): Promise<void> {
  await emailInput(page).fill(user.email);
  await passwordInput(page).fill(user.password);
  await signInButton(page).click();
}

/**
 * Full positive login round trip: open the protected target, sign in at the
 * hosted service, and wait until the browser is back on the target's host.
 *
 * Requires a fresh browser context (no hosted SSO cookie): the form MUST
 * appear. For navigation that may silently SSO instead, use
 * completeHostedLoginIfFormShown.
 */
export async function loginViaHosted(
  page: Page,
  opts: { targetUrl: string; user: HostedUser }
): Promise<void> {
  const targetHost = new URL(opts.targetUrl).hostname;
  await page.goto(opts.targetUrl, { waitUntil: "domcontentloaded" });
  await waitForHostedSignInPage(page);
  await submitHostedLoginForm(page, opts.user);
  await page.waitForURL((url) => url.hostname === targetHost, {
    timeout: timeouts.long,
  });
}

/**
 * Silent-SSO-tolerant login completion: after a navigation that may either
 * show the hosted credentials form or complete silently (the hosted session
 * is still alive), submit the form only if it renders, then wait until back
 * on the target host.
 */
export async function completeHostedLoginIfFormShown(
  page: Page,
  targetHost: string,
  user: HostedUser
): Promise<void> {
  try {
    await passwordInput(page).waitFor({ state: "visible", timeout: timeouts.medium });
    await submitHostedLoginForm(page, user);
  } catch {
    // form never rendered: silent SSO is completing the round trip
  }
  await page.waitForURL((url) => url.hostname === targetHost, {
    timeout: timeouts.long,
  });
}

// ---------------------------------------------------------------------------
// Negative-path assertions
// ---------------------------------------------------------------------------

/**
 * Copy shown by the hosted UI when credentials are rejected (see the live-UI
 * facts in the module header). `invalid credential` is kept as a tolerant
 * alternate because Firebase's copy varies slightly per rejection cause.
 */
const INVALID_CREDENTIALS_COPY =
  /supplied auth credential is malformed or has expired|invalid credential/i;

/**
 * Assert the hosted service rejected the credentials: an alert with the
 * rejection copy is visible and the browser is still on the hosted service.
 */
export async function expectInvalidCredentialsError(page: Page): Promise<void> {
  const alert = page.getByRole("alert").filter({ hasText: INVALID_CREDENTIALS_COPY }).first();
  await expect(
    alert,
    "hosted service should show the invalid-credentials alert"
  ).toBeVisible({ timeout: timeouts.long });
  expect(new URL(page.url()).hostname, "should still be on the hosted service").toBe(
    HOSTED_HOSTNAME
  );
}

/**
 * Assert the hosted sign-in form blocks submission while fields are empty:
 * the live UI disables the submit button (there is no native `required`
 * validation), so a user cannot submit empty or partial credentials at all.
 */
export async function expectEmptyFieldsBlocked(page: Page): Promise<void> {
  const button = signInButton(page);

  await expect(
    button,
    "submit should be disabled while both fields are empty"
  ).toBeDisabled();

  // Partial input (email only) must not enable submission either.
  await emailInput(page).fill("someone@example.com");
  await expect(
    button,
    "submit should stay disabled while the password is empty"
  ).toBeDisabled();
}

/**
 * Assert the route holds no session: a protected internal endpoint must
 * answer with a sign-in redirect, whose target URL is returned for further
 * assertions.
 */
export async function expectSignInRedirect(page: Page, routeUrl: string): Promise<URL> {
  const response = await page.request.get(`${routeUrl}${paths.user}`, {
    ignoreHTTPSErrors: true,
    maxRedirects: 0,
  });
  expect(
    response.status(),
    `unauthenticated ${paths.user} must redirect to sign-in`
  ).toBe(302);
  return new URL(response.headers()["location"] || "");
}

// ---------------------------------------------------------------------------
// Positive-path assertions
// ---------------------------------------------------------------------------

/** Parse the pomerium/verify /json echo into a lowercase-keyed header map. */
async function readEchoedHeaders(response: APIResponse): Promise<Record<string, string>> {
  const body = (await response.json()) as { headers?: Record<string, unknown> };
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(body.headers ?? {})) {
    headers[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : String(value);
  }
  return headers;
}

/**
 * Assert the route serves the authenticated user: the verify upstream's /json
 * echo must be reachable (200) and carry the user's email identity header.
 */
export async function expectUpstreamSeesUser(
  page: Page,
  routeUrl: string,
  email: string
): Promise<void> {
  const response = await page.request.get(`${routeUrl}/json`, {
    ignoreHTTPSErrors: true,
  });
  expect(response.status(), "authenticated request must reach the upstream").toBe(200);
  const headers = await readEchoedHeaders(response);
  expect(headers[headerNames.claimEmail]).toContain(email);
}

/** Assert a Pomerium session cookie exists for the given route URL. */
export async function expectSessionCookie(page: Page, routeUrl: string): Promise<void> {
  const cookies = await page.context().cookies(routeUrl);
  expect(
    cookies.some((cookie) => cookie.name === cookieNames.session),
    `${cookieNames.session} session cookie should be set`
  ).toBe(true);
}

// ---------------------------------------------------------------------------
// Sign-out confirmation page (rendered by the hosted service in BOTH flows -
// verified manually: old and new HA show the same confirmation window).
// ---------------------------------------------------------------------------

function signOutConfirmButton(page: Page): Locator {
  return page.getByRole("button", { name: /^(ok|log ?out|sign ?out|yes)/i }).first();
}

function signOutCancelButton(page: Page): Locator {
  return page.getByRole("button", { name: /cancel|no/i }).first();
}

/** Wait for the hosted sign-out confirmation page (confirm + cancel visible). */
export async function waitForHostedSignOutConfirm(page: Page): Promise<void> {
  await page.waitForURL((url) => url.hostname === HOSTED_HOSTNAME, {
    timeout: timeouts.long,
  });
  await expect(
    signOutConfirmButton(page),
    "hosted sign-out confirm button should be visible"
  ).toBeVisible({ timeout: timeouts.long });
  await expect(
    signOutCancelButton(page),
    "hosted sign-out cancel button should be visible"
  ).toBeVisible();
}

/**
 * Click confirm or cancel on the hosted sign-out page and let it settle.
 *
 * NOTE for callers: the resulting signed-out page can still hold pending
 * activity (a late redirect) - make the NEXT navigation with
 * {@link gotoStable}, or a plain page.goto may abort with net::ERR_ABORTED.
 */
export async function confirmHostedSignOut(
  page: Page,
  action: "confirm" | "cancel"
): Promise<void> {
  const button = action === "confirm" ? signOutConfirmButton(page) : signOutCancelButton(page);
  await button.click();
  await page.waitForLoadState("domcontentloaded");
  if (action === "confirm") {
    // The hosted SPA renders "User has been logged out." optimistically while
    // its revocation request may still be in flight; navigating away inside
    // that window can silently re-authenticate (the session isn't dead yet).
    // Wait for the page's network to settle plus a small propagation buffer
    // (measured: settles in ~1-2s against the live service).
    await page.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => {});
    await page.waitForTimeout(1_000);
  }
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/**
 * page.goto that retries transient navigation aborts. The hosted signed-out
 * page can still hold a pending redirect when a test navigates away from it,
 * which Chromium surfaces as net::ERR_ABORTED on our navigation; container
 * churn can likewise surface ERR_NETWORK_CHANGED. Retrying only the
 * navigation lets the pending activity settle (mirrors
 * suites/upstream-tls/helpers/nav.ts).
 */
export async function gotoStable(
  page: Page,
  url: string,
  attempts = 4
): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await page.goto(url, { waitUntil: "domcontentloaded" });
      return;
    } catch (err) {
      if (attempt < attempts && /ERR_ABORTED|ERR_NETWORK_CHANGED/.test(String(err))) {
        await page.waitForTimeout(500);
        continue;
      }
      throw err;
    }
  }
}

export interface RequestTracker {
  /** URLs of all matching requests seen so far. */
  urls: () => string[];
  /** Stop recording. */
  dispose: () => void;
}

/**
 * Record every request whose URL matches the predicate. Use for NEGATIVE
 * assertions ("this host was never contacted"); for positive "the round trip
 * happened" checks prefer the one-shot page.waitForRequest.
 */
export function trackRequests(page: Page, predicate: (url: URL) => boolean): RequestTracker {
  const seen: string[] = [];
  const listener = (request: { url: () => string }) => {
    try {
      const url = new URL(request.url());
      if (predicate(url)) {
        seen.push(url.toString());
      }
    } catch {
      // ignore non-parseable URLs (data:, about:)
    }
  };
  page.on("request", listener);
  return {
    urls: () => [...seen],
    dispose: () => page.off("request", listener),
  };
}

/**
 * Decode a compact JWS (header.payload.signature) without verifying the
 * signature - structural assertions only.
 */
export function decodeCompactJws(jws: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
} {
  const parts = jws.split(".");
  expect(parts, "a compact JWS has exactly 3 dot-separated segments").toHaveLength(3);
  const decode = (segment: string) =>
    JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
  return { header: decode(parts[0]), payload: decode(parts[1]) };
}
