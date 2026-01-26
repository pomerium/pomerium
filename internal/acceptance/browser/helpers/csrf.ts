/**
 * CSRF token handling helpers for E2E acceptance tests.
 * Provides functions to extract and manipulate CSRF tokens.
 */

import { Page, expect } from "@playwright/test";
import { urls, paths, cookieNames } from "../fixtures/test-data.js";

/**
 * CSRF token information.
 */
export interface CSRFInfo {
  /** The CSRF token value */
  token: string;
  /** Source of the token (cookie or query param) */
  source: "cookie" | "query" | "header" | "body";
}

/**
 * Extract the CSRF token from the current page state.
 * Tries multiple sources: query params, cookies, hidden form fields.
 */
export async function extractCSRFToken(page: Page): Promise<CSRFInfo | null> {
  // Try query params first (from sign_in redirect)
  const url = new URL(page.url());
  const queryToken = url.searchParams.get("pomerium_csrf");
  if (queryToken) {
    return { token: queryToken, source: "query" };
  }

  // Try hidden form field
  const formToken = await page
    .locator('input[name="pomerium_csrf"]')
    .first()
    .getAttribute("value")
    .catch(() => null);
  if (formToken) {
    return { token: formToken, source: "body" };
  }

  // Try CSRF cookie (this is encoded, may need decoding)
  const cookies = await page.context().cookies();
  const csrfCookie = cookies.find((c) => c.name === cookieNames.csrf);
  if (csrfCookie) {
    return { token: csrfCookie.value, source: "cookie" };
  }

  return null;
}

/**
 * Get the CSRF token from the authenticate service.
 * Makes a request to trigger CSRF cookie generation if needed.
 */
export async function getCSRFTokenFromAuthenticate(page: Page): Promise<string | null> {
  // Navigate to sign_in which sets the CSRF cookie
  const signInUrl = `${urls.authenticate}${paths.signIn}`;

  // Make a request to get CSRF cookie set
  await page.goto(signInUrl, {
    waitUntil: "domcontentloaded",
  });

  // Extract token
  const csrf = await extractCSRFToken(page);
  return csrf?.token ?? null;
}

/**
 * Tamper with the CSRF token in cookies.
 * Used for negative tests to verify CSRF protection.
 */
export async function tamperCSRFCookie(page: Page): Promise<void> {
  const cookies = await page.context().cookies();
  const csrfCookie = cookies.find((c) => c.name === cookieNames.csrf);

  if (!csrfCookie) {
    throw new Error("No CSRF cookie found to tamper");
  }

  // Replace with invalid value
  await page.context().addCookies([
    {
      name: csrfCookie.name,
      value: "tampered-invalid-csrf-token-value",
      domain: csrfCookie.domain,
      path: csrfCookie.path,
      expires: csrfCookie.expires,
      httpOnly: csrfCookie.httpOnly,
      secure: csrfCookie.secure,
      sameSite: csrfCookie.sameSite,
    },
  ]);
}

/**
 * Remove the CSRF cookie entirely.
 * Used for negative tests.
 */
export async function removeCSRFCookie(page: Page): Promise<void> {
  const cookies = await page.context().cookies();
  const otherCookies = cookies.filter((c) => c.name !== cookieNames.csrf);

  await page.context().clearCookies();
  if (otherCookies.length > 0) {
    await page.context().addCookies(otherCookies);
  }
}

/**
 * Verify that CSRF validation rejects tampered tokens.
 */
export async function verifyCSRFTamperRejected(
  page: Page,
  targetUrl: string
): Promise<void> {
  // Navigate to target with tampered CSRF
  const response = await page.goto(targetUrl, {
    waitUntil: "domcontentloaded",
  });

  // Should get an error response
  expect(response).not.toBeNull();

  // CSRF errors typically result in 400 or redirect to login
  const status = response!.status();
  const isError = status >= 400 || status === 302;

  if (!isError) {
    // Check page content for CSRF error message
    const content = await page.content();
    expect(
      content.toLowerCase(),
      "Response should indicate CSRF error"
    ).toMatch(/csrf|invalid|forbidden|error/i);
  }
}

/**
 * Verify that the state parameter in OAuth flow contains CSRF protection.
 */
export async function verifyOAuthStateContainsCSRF(page: Page): Promise<void> {
  // Navigate to trigger OAuth redirect
  await page.goto(urls.app, {
    waitUntil: "domcontentloaded",
  });

  // Wait for redirect to Keycloak
  await page.waitForURL((url) => url.toString().includes("keycloak"), {
    timeout: 10000,
  });

  const url = new URL(page.url());
  const state = url.searchParams.get("state");

  expect(state, "OAuth state parameter should be present").toBeDefined();
  expect(
    state!.length,
    "OAuth state should have sufficient length for security"
  ).toBeGreaterThan(20);

  // Pomerium's state contains base64-encoded structured data with signature
  // The exact format is an implementation detail, but it should:
  // 1. Have high entropy (long base64-like string)
  // 2. Be cryptographically signed (long enough for HMAC)
  // The minimum secure length for CSRF state is typically 128+ characters
  expect(
    state!.length,
    "OAuth state should be cryptographically secure (long enough for signature)"
  ).toBeGreaterThan(100);
}

/**
 * Tamper with the OAuth state parameter.
 * Returns a URL with modified state for testing validation.
 */
export function createTamperedCallbackUrl(
  originalUrl: string,
  tamperedState: string
): string {
  const url = new URL(originalUrl);
  url.searchParams.set("state", tamperedState);
  return url.toString();
}

/**
 * Build a logout URL with CSRF token.
 * Uses the app domain since that's where the session cookie is scoped.
 */
export function buildLogoutUrl(csrfToken: string): string {
  const url = new URL(paths.signOut, urls.app);
  url.searchParams.set("pomerium_csrf", csrfToken);
  return url.toString();
}

/**
 * Build a logout URL without CSRF token (for negative testing).
 */
export function buildLogoutUrlWithoutCSRF(): string {
  return `${urls.app}${paths.signOut}`;
}
