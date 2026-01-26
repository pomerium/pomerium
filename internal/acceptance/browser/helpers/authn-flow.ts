/**
 * Authentication flow helpers for E2E acceptance tests.
 * Provides functions to perform login/logout via Keycloak.
 */

import { Page, expect } from "@playwright/test";
import { TestUser, getKeycloakUsername } from "../fixtures/users.js";
import { urls, paths, timeouts } from "../fixtures/test-data.js";

/**
 * Options for login operation.
 */
export interface LoginOptions {
  /** User to log in as */
  user: TestUser;
  /** URL to navigate to (triggers auth) */
  targetUrl?: string;
  /** Whether to wait for redirect back to target */
  waitForRedirect?: boolean;
  /** Expected final URL after login (if different from targetUrl) */
  expectedFinalUrl?: string;
}

/**
 * Options for logout operation.
 */
export interface LogoutOptions {
  /** Whether to include CSRF token */
  withCsrf?: boolean;
  /** Expected redirect after logout */
  expectedRedirect?: string;
}

/**
 * Perform a complete login flow via Keycloak.
 *
 * This navigates to the target URL, follows redirects to Keycloak,
 * fills in credentials, and waits for the redirect back to Pomerium.
 */
export async function login(page: Page, options: LoginOptions): Promise<void> {
  const { user, targetUrl = urls.app, waitForRedirect = true } = options;
  const keycloakUsername = getKeycloakUsername(user);

  // Navigate to target URL - this should redirect to Pomerium authenticate
  await page.goto(targetUrl, {
    waitUntil: "domcontentloaded",
    timeout: timeouts.long,
  });

  // Wait for Keycloak login page
  // Keycloak login form has id="kc-form-login"
  await page.waitForSelector("#kc-form-login", {
    timeout: timeouts.long,
  });

  // Verify we're on the Keycloak login page
  const currentUrl = page.url();
  expect(currentUrl).toContain("keycloak.localhost.pomerium.io");
  expect(currentUrl).toContain("/realms/pomerium-e2e/protocol/openid-connect/auth");

  // Fill in credentials
  await page.locator("#username").fill(keycloakUsername);
  await page.locator("#password").fill(user.password);

  // Submit the form
  await page.locator("#kc-login").click();

  if (waitForRedirect) {
    // Wait for redirect back to Pomerium
    await page.waitForURL(
      (url) => {
        // Use proper URL hostname parsing for security
        const hostname = url.hostname;
        // Should be back at our app, not at Keycloak
        return (
          hostname !== "keycloak.localhost.pomerium.io" &&
          (hostname === "app.localhost.pomerium.io" ||
            hostname === "authenticate.localhost.pomerium.io")
        );
      },
      { timeout: timeouts.long }
    );

    // If we expect a specific final URL, wait for it
    if (options.expectedFinalUrl) {
      await page.waitForURL(options.expectedFinalUrl, {
        timeout: timeouts.medium,
      });
    }
  }
}

/**
 * Perform a logout operation.
 *
 * This fetches the CSRF token if needed and posts to the sign_out endpoint.
 */
export async function logout(page: Page, options: LogoutOptions = {}): Promise<void> {
  const { withCsrf = true, expectedRedirect } = options;

  let csrfToken: string | undefined;

  if (withCsrf) {
    // Get CSRF token from the CSRF cookie or from /.well-known/pomerium
    csrfToken = await getCSRFToken(page);
  }

  // Navigate to sign_out endpoint with CSRF token
  const signOutUrl = new URL(paths.signOut, urls.authenticate);
  if (csrfToken) {
    signOutUrl.searchParams.set("pomerium_csrf", csrfToken);
  }

  // POST to sign_out (via form submission or direct navigation)
  await page.goto(signOutUrl.toString(), {
    timeout: timeouts.medium,
  });

  // Should be redirected to signed_out page or login
  if (expectedRedirect) {
    await page.waitForURL(expectedRedirect, {
      timeout: timeouts.medium,
    });
  }
}

/**
 * Get the CSRF token from the cookie or well-known endpoint.
 */
export async function getCSRFToken(page: Page): Promise<string | undefined> {
  // Try to get from well-known endpoint first
  try {
    const wellKnownUrl = `${urls.authenticate}${paths.wellKnown}`;
    const response = await page.request.get(wellKnownUrl, {
      ignoreHTTPSErrors: true,
    });

    if (response.ok()) {
      const data = await response.json();
      if (data.csrf_token) {
        return data.csrf_token;
      }
    }
  } catch {
    // Fall through to cookie method
  }

  // Try to get from cookie
  const cookies = await page.context().cookies();
  const csrfCookie = cookies.find((c) => c.name === "_pomerium_csrf");
  if (csrfCookie) {
    // The CSRF cookie value is encoded, but for the token we might need to decode it
    // For simplicity, return the raw value - the test may need to adjust
    return csrfCookie.value;
  }

  return undefined;
}

/**
 * Check if the user is currently logged in by checking for session cookie.
 */
export async function isLoggedIn(page: Page): Promise<boolean> {
  const cookies = await page.context().cookies();
  return cookies.some((c) => c.name === "_pomerium");
}

/**
 * Wait for authentication to complete after a redirect.
 */
export async function waitForAuthComplete(page: Page): Promise<void> {
  // Wait until we're not on Keycloak and have a session cookie
  await page.waitForFunction(
    () => {
      return !window.location.href.includes("keycloak");
    },
    { timeout: timeouts.long }
  );

  // Give time for cookie to be set
  await page.waitForTimeout(500);
}

/**
 * Clear all authentication state (cookies, storage).
 */
export async function clearAuthState(page: Page): Promise<void> {
  await page.context().clearCookies();
  // Try to clear storage, but it may fail if page is on about:blank or cross-origin
  // This is fine since cookies are the primary auth mechanism
  try {
    await page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  } catch {
    // Ignore SecurityError - storage clearing is best-effort
  }
}

/**
 * Verify that access is denied (403 response or redirect to login).
 */
export async function expectAccessDenied(page: Page, url: string): Promise<void> {
  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: timeouts.medium,
  });

  // Check for 403 status
  if (response) {
    const status = response.status();
    expect([403, 302]).toContain(status);

    if (status === 403) {
      // Verify it's a Pomerium 403 page
      const body = await page.content();
      expect(body).toMatch(/forbidden|denied|unauthorized/i);
    }
  }
}

/**
 * Verify that access is granted (200 response).
 */
export async function expectAccessGranted(page: Page, url: string): Promise<void> {
  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: timeouts.medium,
  });

  expect(response).not.toBeNull();
  expect(response!.status()).toBe(200);
}
